// RedVital — identidad-service
// T-304.4 → GET /.well-known/jwks.json (ruta exacta del contrato).
// Además publica /.well-known/openid-configuration: un documento mínimo que
// solo indica el emisor y dónde están las claves. Lo necesitan el plugin
// openid-connect de APISIX (T-305.2) y la validación de Campañas para
// encontrar el JWKS por convención. No convierte a Identidad en un proveedor
// OpenID completo: no hay flujos de autorización, solo el puntero al JWKS.

using Microsoft.AspNetCore.Mvc;
using RedVital.Identidad.Aplicacion.CasosDeUso;

namespace RedVital.Identidad.Api.Controllers;

[ApiController]
public class JwksController : ControllerBase
{
    private readonly ObtenerClavesPublicas _obtenerClavesPublicas;
    private readonly IConfiguration _configuracion;

    public JwksController(ObtenerClavesPublicas obtenerClavesPublicas, IConfiguration configuracion)
    {
        _obtenerClavesPublicas = obtenerClavesPublicas;
        _configuracion = configuracion;
    }

    /// <summary>T-304.4</summary>
    [HttpGet("/.well-known/jwks.json")]
    [ResponseCache(Duration = 300)]
    public async Task<IActionResult> JwksAsync(CancellationToken ct) =>
        Ok(await _obtenerClavesPublicas.EjecutarAsync(ct));

    [HttpGet("/.well-known/openid-configuration")]
    public IActionResult Descubrimiento() => Ok(new
    {
        issuer = _configuracion["Jwt:Emisor"],
        jwks_uri = _configuracion["Jwt:JwksUriInterna"],
        id_token_signing_alg_values_supported = new[] { "RS256" },
    });
}
