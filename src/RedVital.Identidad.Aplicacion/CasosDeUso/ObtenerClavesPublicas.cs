// RedVital — identidad-service
// T-304.4 — Endpoint de claves públicas (JWKS).
// Habilita la validación real en el Gateway (APISIX la consume en T-305.2).
// Formato exacto RFC 7517, confirmado contra identidad-openapi.yaml real:
// kty, kid, use, alg, n, e — sin el "d" (exponente privado), por supuesto.

using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Aplicacion.CasosDeUso;

public record JwkRespuesta(string Kty, string Kid, string Use, string Alg, string N, string E);
public record JwksRespuesta(List<JwkRespuesta> Keys);

public class ObtenerClavesPublicas
{
    private readonly IdentidadDbContext _contexto;

    public ObtenerClavesPublicas(IdentidadDbContext contexto) => _contexto = contexto;

    /// <summary>
    /// Devuelve TODAS las claves todavía publicadas (RetiradaEn es nulo o
    /// futuro) — en particular, durante una rotación, esto incluye la clave
    /// anterior Y la nueva a la vez. Es justo lo que hace que un token
    /// firmado antes de rotar siga validando sin caída (ADR-008, punto 9-10).
    /// </summary>
    public async Task<JwksRespuesta> EjecutarAsync(CancellationToken ct = default)
    {
        var ahora = DateTimeOffset.UtcNow;

        var llaves = await _contexto.LlavesFirma
            .Where(k => k.RetiradaEn == null || k.RetiradaEn > ahora)
            .ToListAsync(ct);

        var jwks = llaves.Select(llave =>
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(llave.ClavePublicaPem);
            var parametros = rsa.ExportParameters(includePrivateParameters: false);

            return new JwkRespuesta(
                Kty: "RSA",
                Kid: llave.Kid,
                Use: "sig",
                Alg: "RS256",
                N: Base64UrlSinRelleno(parametros.Modulus!),
                E: Base64UrlSinRelleno(parametros.Exponent!));
        }).ToList();

        return new JwksRespuesta(jwks);
    }

    private static string Base64UrlSinRelleno(byte[] datos) =>
        Convert.ToBase64String(datos).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
