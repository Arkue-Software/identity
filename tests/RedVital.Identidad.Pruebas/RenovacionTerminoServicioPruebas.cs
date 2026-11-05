// T-330.5 — Pruebas de renovación (T-330.1), término (T-330.2), token de
// servicio (T-330.3) y auditoría (T-330.4).

using System.IdentityModel.Tokens.Jwt;
using RedVital.Identidad.Dominio;
using Xunit;

namespace RedVital.Identidad.Pruebas;

public class RenovacionTerminoServicioPruebas
{
    private static async Task<(Entorno e, string cookie)> SesionIniciadaAsync()
    {
        var e = new Entorno();
        e.CrearOperador();
        var r = await e.IniciarSesion().EjecutarAsync(new("operador@banco-ficticio.test", "Clave-Prueba-123", null), "corr-inicio");
        return (e, r.CookieRenovacion!);
    }

    [Fact] // T-330.1
    public async Task Renovar_emite_token_nuevo_y_rota_el_secreto_sin_extender_la_vigencia()
    {
        var (e, cookie) = await SesionIniciadaAsync();
        var expiraOriginal = e.Contexto.Sesiones.Single().ExpiraEn;

        var r = await e.RenovarSesion().EjecutarAsync(cookie, "corr-renovar");

        Assert.True(r.Exitoso);
        Assert.NotNull(r.TokenAcceso);
        Assert.NotEqual(cookie, r.CookieRenovacionNueva);
        Assert.Equal(expiraOriginal, r.CookieExpira); // vigencia absoluta de 8 h
    }

    [Fact] // T-330.1: reutilizar un secreto ya rotado revoca toda la sesión
    public async Task Reutilizar_el_secreto_anterior_revoca_la_sesion()
    {
        var (e, cookieVieja) = await SesionIniciadaAsync();
        var renovada = await e.RenovarSesion().EjecutarAsync(cookieVieja, "corr-a");

        var reutilizada = await e.RenovarSesion().EjecutarAsync(cookieVieja, "corr-b");
        var conLaNueva = await e.RenovarSesion().EjecutarAsync(renovada.CookieRenovacionNueva!, "corr-c");

        Assert.False(reutilizada.Exitoso);
        Assert.True(reutilizada.DetectadaReutilizacion);
        Assert.False(conLaNueva.Exitoso); // la sesión entera quedó revocada
        Assert.Equal("reutilizacion", e.Contexto.Sesiones.Single().MotivoRevocacion);
    }

    [Fact] // T-330.1: pasada la vigencia de 8 h ya no se renueva
    public async Task Sesion_vencida_no_se_renueva()
    {
        var (e, cookie) = await SesionIniciadaAsync();
        e.Contexto.Sesiones.Single().ExpiraEn = DateTimeOffset.UtcNow.AddSeconds(-1);
        e.Contexto.SaveChanges();

        var r = await e.RenovarSesion().EjecutarAsync(cookie, "corr-vencida");

        Assert.False(r.Exitoso);
    }

    [Fact] // T-330.2
    public async Task Cerrar_sesion_la_revoca_y_la_renovacion_posterior_falla()
    {
        var (e, cookie) = await SesionIniciadaAsync();
        var sesionId = Guid.Parse(cookie.Split('.')[0]);

        Assert.True(await e.CerrarSesion().EjecutarAsync(sesionId, "corr-cierre"));
        var r = await e.RenovarSesion().EjecutarAsync(cookie, "corr-despues");

        Assert.False(r.Exitoso);
        Assert.Equal("cierre", e.Contexto.Sesiones.Single().MotivoRevocacion);
        Assert.False(await e.CerrarSesion().EjecutarAsync(sesionId, "corr-otra-vez")); // cerrar dos veces no falla
    }

    [Fact] // T-330.2: desactivar la cuenta revoca todas sus sesiones
    public async Task Desactivacion_revoca_todas_las_sesiones()
    {
        var (e, _) = await SesionIniciadaAsync();
        await e.IniciarSesion().EjecutarAsync(new("operador@banco-ficticio.test", "Clave-Prueba-123", null), "corr-2");
        var usuarioId = e.Contexto.Usuarios.Single().Id;

        await e.CerrarSesion().RevocarTodasPorDesactivacionAsync(usuarioId, "corr-desactivar");

        Assert.All(e.Contexto.Sesiones, s => Assert.Equal("desactivacion", s.MotivoRevocacion));
    }

    [Fact] // T-330.3
    public async Task Token_de_servicio_de_Donacion_lleva_rol_servicio_y_sin_jurisdiccion()
    {
        var e = new Entorno();
        e.CrearCredencialServicio("donacion", "secreto-donacion");

        var r = await e.EmitirTokenServicio().EjecutarAsync(new("donacion", "secreto-donacion"), "corr-svc");

        Assert.True(r.Exitoso);
        var claims = new JwtSecurityTokenHandler().ReadJwtToken(r.TokenAcceso).Claims.ToDictionary(c => c.Type, c => c.Value);
        Assert.Equal("donacion", claims["sub"]);
        Assert.Equal("servicio", claims["role"]);
        Assert.Equal("", claims["jurisdiction"]);
    }

    [Theory] // T-330.3: secreto incorrecto o cliente no reconocido
    [InlineData("donacion", "secreto-equivocado")]
    [InlineData("institucional", "secreto-donacion")]
    public async Task Token_de_servicio_rechaza_credenciales_invalidas(string cliente, string secreto)
    {
        var e = new Entorno();
        e.CrearCredencialServicio("donacion", "secreto-donacion");

        var r = await e.EmitirTokenServicio().EjecutarAsync(new(cliente, secreto), "corr-svc-mal");

        Assert.False(r.Exitoso);
    }

    [Fact] // T-330.4: el ciclo completo queda en la bitácora, con correlación y sin datos del recurso
    public async Task Ciclo_de_sesion_queda_auditado()
    {
        var (e, cookie) = await SesionIniciadaAsync();
        var renovada = await e.RenovarSesion().EjecutarAsync(cookie, "corr-renovar");
        await e.CerrarSesion().EjecutarAsync(Guid.Parse(renovada.CookieRenovacionNueva!.Split('.')[0]), "corr-cerrar");

        var operaciones = e.Contexto.RegistroAuditoriaIdent.Select(r => r.Operacion).ToList();
        Assert.Equal(3, operaciones.Count);
        Assert.Contains("inicio_sesion", operaciones);
        Assert.Contains("renovacion_sesion", operaciones);
        Assert.Contains("cierre_sesion", operaciones);
        Assert.All(e.Contexto.RegistroAuditoriaIdent, r => Assert.False(string.IsNullOrEmpty(r.CorrelacionId)));

        // La entidad de auditoría no tiene ningún campo para el contenido del recurso.
        var propiedades = typeof(RegistroAuditoriaIdent).GetProperties().Select(p => p.Name);
        Assert.DoesNotContain(propiedades, n => n.Contains("Detalle") || n.Contains("Payload") || n.Contains("Contenido"));
    }
}
