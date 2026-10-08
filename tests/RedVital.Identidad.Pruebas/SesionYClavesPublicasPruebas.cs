// T-304.5 — Pruebas unitarias/integración de sesión (T-304.2, T-304.3) y
// claves públicas (T-304.4).

using System.IdentityModel.Tokens.Jwt;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RedVital.Identidad.Aplicacion.CasosDeUso;
using RedVital.Identidad.Dominio;
using Xunit;

namespace RedVital.Identidad.Pruebas;

public class SesionYClavesPublicasPruebas
{
    private static readonly string[] OchoReivindicaciones = { "sub", "role", "jurisdiction", "iss", "aud", "iat", "exp", "jti" };

    [Fact] // T-304.2 + T-304.3
    public async Task Credencial_correcta_emite_token_RS256_de_15_minutos_con_ocho_reivindicaciones()
    {
        var e = new Entorno();
        var usuario = e.CrearOperador();

        var r = await e.IniciarSesion().EjecutarAsync(new("operador@banco-ficticio.test", "Clave-Prueba-123", "127.0.0.1"), "corr-1");

        Assert.True(r.Exitoso);
        var token = new JwtSecurityTokenHandler().ReadJwtToken(r.TokenAcceso);
        Assert.Equal("RS256", token.Header.Alg);
        Assert.Equal(e.Llave.Kid, token.Header.Kid);
        Assert.Equal(OchoReivindicaciones.OrderBy(x => x), token.Claims.Select(c => c.Type).OrderBy(x => x));
        Assert.Equal(usuario.Id.ToString(), token.Claims.Single(c => c.Type == "sub").Value);
        Assert.Equal($"institucion:{Entorno.Institucion}", token.Claims.Single(c => c.Type == "jurisdiction").Value);

        var iat = long.Parse(token.Claims.Single(c => c.Type == "iat").Value);
        var exp = long.Parse(token.Claims.Single(c => c.Type == "exp").Value);
        Assert.Equal(900, exp - iat);
    }

    [Fact] // T-304.3: el token no transporta datos personales
    public async Task Token_no_contiene_correo_ni_nombre()
    {
        var e = new Entorno();
        e.CrearOperador();
        var r = await e.IniciarSesion().EjecutarAsync(new("operador@banco-ficticio.test", "Clave-Prueba-123", null), "corr-2");

        var valores = new JwtSecurityTokenHandler().ReadJwtToken(r.TokenAcceso).Claims.Select(c => c.Value);
        Assert.DoesNotContain(valores, v => v.Contains("operador@banco-ficticio.test"));
    }

    [Fact] // T-304.2: inicio de sesión fija la cookie de renovación de 8 horas
    public async Task Inicio_de_sesion_crea_sesion_de_renovacion_de_ocho_horas()
    {
        var e = new Entorno();
        e.CrearOperador();
        var r = await e.IniciarSesion().EjecutarAsync(new("operador@banco-ficticio.test", "Clave-Prueba-123", null), "corr-3");

        var sesion = e.Contexto.Sesiones.Single();
        Assert.Equal(TimeSpan.FromHours(8), sesion.ExpiraEn - sesion.EmitidaEn);
        Assert.StartsWith(sesion.Id.ToString() + ".", r.CookieRenovacion);
        Assert.DoesNotContain(r.CookieRenovacion!.Split('.')[1], sesion.SecretoHash); // nunca se guarda en claro
    }

    [Theory] // T-304.2: mismo resultado para usuario inexistente y credencial incorrecta
    [InlineData("operador@banco-ficticio.test", "clave-equivocada")]
    [InlineData("nadie@banco-ficticio.test", "Clave-Prueba-123")]
    public async Task Credenciales_incorrectas_fallan_igual_y_quedan_auditadas(string correo, string clave)
    {
        var e = new Entorno();
        e.CrearOperador();

        var r = await e.IniciarSesion().EjecutarAsync(new(correo, clave, null), "corr-4");

        Assert.False(r.Exitoso);
        Assert.Null(r.TokenAcceso);
        Assert.Empty(e.Contexto.Sesiones);
        var registro = Assert.Single(e.Contexto.RegistroAuditoriaIdent);
        Assert.Equal("denegado", registro.Resultado);
        Assert.Equal("corr-4", registro.CorrelacionId);
    }

    [Fact] // T-304.3 + T-304.4: el token se valida con lo que publica el JWKS
    public async Task Token_emitido_valida_contra_el_JWKS_publicado()
    {
        var e = new Entorno();
        e.CrearOperador();
        var r = await e.IniciarSesion().EjecutarAsync(new("operador@banco-ficticio.test", "Clave-Prueba-123", null), "corr-5");
        var jwks = await e.ObtenerClavesPublicas().EjecutarAsync();

        var claves = jwks.Keys.Select(k => new JsonWebKey { Kty = k.Kty, Kid = k.Kid, N = k.N, E = k.E, Alg = k.Alg, Use = k.Use });
        var principal = new JwtSecurityTokenHandler { MapInboundClaims = false }.ValidateToken(r.TokenAcceso, new TokenValidationParameters
        {
            ValidIssuer = Entorno.Emisor,
            ValidAudience = Entorno.Audiencia,
            IssuerSigningKeys = claves,
        }, out _);

        Assert.Equal("operador", principal.FindFirst("role")!.Value);
    }

    [Fact] // T-304.4: durante una rotación se publican la clave anterior y la nueva; las retiradas no
    public async Task JWKS_publica_claves_vigentes_y_omite_las_retiradas()
    {
        var e = new Entorno();
        var nueva = new ProveedorDePrueba { Kid = "prueba-2" };
        var retirada = new ProveedorDePrueba { Kid = "prueba-0" };
        e.Contexto.LlavesFirma.Add(new LlaveFirma { Kid = nueva.Kid, ClavePublicaPem = nueva.Rsa.ExportSubjectPublicKeyInfoPem(), ActivaDesde = DateTimeOffset.UtcNow });
        e.Contexto.LlavesFirma.Add(new LlaveFirma { Kid = retirada.Kid, ClavePublicaPem = retirada.Rsa.ExportSubjectPublicKeyInfoPem(), ActivaDesde = DateTimeOffset.UtcNow.AddDays(-30), RetiradaEn = DateTimeOffset.UtcNow.AddHours(-1) });
        e.Contexto.SaveChanges();

        var jwks = await e.ObtenerClavesPublicas().EjecutarAsync();

        Assert.Equal(new[] { "prueba-1", "prueba-2" }, jwks.Keys.Select(k => k.Kid).OrderBy(x => x));
        Assert.All(jwks.Keys, k => { Assert.Equal("RSA", k.Kty); Assert.Equal("RS256", k.Alg); Assert.Equal("sig", k.Use); });
    }

    [Fact] // RF-22: un cambio de jurisdicción se aplica en el siguiente token emitido
    public async Task Cambio_de_jurisdiccion_se_refleja_en_el_siguiente_token()
    {
        var e = new Entorno();
        var usuarioId = e.CrearOperador().Id;
        e.Contexto.ChangeTracker.Clear();
        var usuario = e.Contexto.Usuarios
            .Include(u => u.Jurisdicciones)
            .Single(u => u.Id == usuarioId);
        var otra = Guid.NewGuid();
        var anterior = usuario.Jurisdicciones.Single();
        anterior.VigenteHasta = DateTimeOffset.UtcNow.AddSeconds(-1);
        e.Contexto.UsuarioJurisdicciones.Add(new UsuarioJurisdiccion
        {
            Id = Guid.NewGuid(), UsuarioId = usuario.Id, Ambito = "institucion", InstitucionId = otra,
            AsignadaPor = Guid.NewGuid(), VigenteDesde = DateTimeOffset.UtcNow.AddSeconds(-1),
        });
        e.Contexto.SaveChanges();

        var r = await e.IniciarSesion().EjecutarAsync(new("operador@banco-ficticio.test", "Clave-Prueba-123", null), "corr-6");

        var jurisdiccion = new JwtSecurityTokenHandler().ReadJwtToken(r.TokenAcceso).Claims.Single(c => c.Type == "jurisdiction").Value;
        Assert.Equal($"institucion:{otra}", jurisdiccion);
    }
}
