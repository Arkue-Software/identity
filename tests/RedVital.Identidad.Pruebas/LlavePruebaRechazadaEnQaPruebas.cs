// T-303.3 — Confirma que la configuración de QA rechaza la llave de prueba.
// Tres comprobaciones: (1) criptográfica, (2) de configuración, (3) de código.
// La cuarta, contra el ambiente desplegado, está en
// api-gateway/pruebas/t-303.3-qa-rechaza-llave-prueba.sh.

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using RedVital.Identidad.Aplicacion.CasosDeUso;
using Xunit;

namespace RedVital.Identidad.Pruebas;

public class LlavePruebaRechazadaEnQaPruebas
{
    [Fact] // (1) Un token firmado con la llave de prueba no valida con las claves de QA
    public async Task Token_firmado_con_llave_de_prueba_no_valida_con_el_JWKS_de_QA()
    {
        var qa = new Entorno(); // su JWKS solo contiene la llave real de ese ambiente

        using var llaveDePrueba = RSA.Create(3072);
        var tokenDePrueba = new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(
            claims: new[]
            {
                new Claim("sub", "11111111-1111-1111-1111-111111111111"), new Claim("role", "operador"),
                new Claim("jurisdiction", "institucion:22222222-2222-2222-2222-222222222222"),
                new Claim("iss", Entorno.Emisor), new Claim("aud", Entorno.Audiencia),
                new Claim("iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim("exp", DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim("jti", Guid.NewGuid().ToString()),
            },
            signingCredentials: new SigningCredentials(new RsaSecurityKey(llaveDePrueba) { KeyId = "dev-key-1" }, SecurityAlgorithms.RsaSha256)));

        var jwksQa = await qa.ObtenerClavesPublicas().EjecutarAsync();
        Assert.DoesNotContain(jwksQa.Keys, k => k.Kid == "dev-key-1");

        var claves = jwksQa.Keys.Select(k => new JsonWebKey { Kty = k.Kty, Kid = k.Kid, N = k.N, E = k.E });
        Assert.ThrowsAny<SecurityTokenException>(() =>
            new JwtSecurityTokenHandler().ValidateToken(tokenDePrueba, new TokenValidationParameters
            {
                ValidIssuer = Entorno.Emisor,
                ValidAudience = Entorno.Audiencia,
                IssuerSigningKeys = claves,
            }, out _));
    }

    [Fact] // (2) El perfil de QA no declara ninguna llave de prueba
    public void AppSettings_de_QA_no_referencia_la_llave_de_prueba()
    {
        var qa = File.ReadAllText(Path.Combine(RaizRepositorio(), "src", "RedVital.Identidad.Api", "appsettings.QA.json"));

        Assert.DoesNotContain("LlavePrivadaDesarrollo", qa);
        Assert.DoesNotContain("LlavePublicaDesarrollo", qa);
        Assert.DoesNotContain("dev-signing-key", qa);
    }

    [Fact] // (3) Solo Development registra el proveedor que carga la llave de prueba
    public void Program_solo_usa_el_proveedor_de_desarrollo_en_Development()
    {
        var program = File.ReadAllText(Path.Combine(RaizRepositorio(), "src", "RedVital.Identidad.Api", "Program.cs"));

        Assert.Contains("if (builder.Environment.IsDevelopment())\n    builder.Services.AddSingleton<IProveedorLlaveFirma, ProveedorLlaveFirmaDesarrollo>();",
            program.Replace("\r\n", "\n"));
    }

    private static string RaizRepositorio()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "src")))
            dir = dir.Parent;
        return dir?.FullName ?? throw new DirectoryNotFoundException("No se encontró la raíz del repositorio.");
    }
}
