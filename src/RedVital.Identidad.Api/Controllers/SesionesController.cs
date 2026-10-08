// RedVital — identidad-service
// T-304.2 + T-304.3 → POST   /v1/sesiones
// T-330.1           → POST   /v1/sesiones/renovacion
// T-330.2           → DELETE /v1/sesiones/actual
// Rutas, cabeceras y errores alineados con identidad-openapi.yaml y con
// increment-operations-sprint-3.md (repositorio RedVital/api).

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RedVital.Identidad.Api.Soporte;
using RedVital.Identidad.Aplicacion.CasosDeUso;

namespace RedVital.Identidad.Api.Controllers;

public record IniciarSesionPeticion(string Correo, string Credencial);
public record TokenRespuesta(string TokenAcceso, string Tipo, int ExpiraEn);

[ApiController]
[Route("v1/sesiones")]
public class SesionesController : ControllerBase
{
    private const string NombreCookie = "redvital_renovacion";

    // El navegador ve /api/v1/sesiones: el gateway quita "/api" antes de
    // reenviar, pero la cookie se evalúa contra la ruta que ve el navegador.
    private const string RutaCookie = "/api/v1/sesiones";

    private readonly IniciarSesion _iniciarSesion;
    private readonly RenovarSesion _renovarSesion;
    private readonly CerrarSesion _cerrarSesion;

    public SesionesController(IniciarSesion iniciarSesion, RenovarSesion renovarSesion, CerrarSesion cerrarSesion)
    {
        _iniciarSesion = iniciarSesion;
        _renovarSesion = renovarSesion;
        _cerrarSesion = cerrarSesion;
    }

    /// <summary>T-304.2 + T-304.3</summary>
    [HttpPost]
    public async Task<IActionResult> IniciarAsync([FromBody] IniciarSesionPeticion peticion, CancellationToken ct)
    {
        var correlacionId = HttpContext.CorrelacionId();
        var resultado = await _iniciarSesion.EjecutarAsync(
            new IniciarSesionSolicitud(peticion.Correo, peticion.Credencial, HttpContext.Connection.RemoteIpAddress?.ToString()),
            correlacionId, ct);

        // Mismo mensaje para "no existe" y "credencial incorrecta" (SRS V3, RF-23).
        if (!resultado.Exitoso)
            return Problemas.SesionInvalida(correlacionId, "El correo o la credencial no son correctos.");

        FijarCookie(resultado.CookieRenovacion!, resultado.CookieExpira!.Value);
        return Ok(new TokenRespuesta(resultado.TokenAcceso!, "Bearer", resultado.ExpiraEnSegundos));
    }

    /// <summary>T-330.1</summary>
    [HttpPost("renovacion")]
    public async Task<IActionResult> RenovarAsync(CancellationToken ct)
    {
        var correlacionId = HttpContext.CorrelacionId();
        if (!Request.Cookies.TryGetValue(NombreCookie, out var cookie) || string.IsNullOrEmpty(cookie))
            return Problemas.SesionInvalida(correlacionId, "No hay una sesión para renovar.");

        var resultado = await _renovarSesion.EjecutarAsync(cookie, correlacionId, ct);
        if (!resultado.Exitoso)
        {
            BorrarCookie();
            return Problemas.SesionInvalida(correlacionId, "La sesión no es válida o ya expiró.");
        }

        FijarCookie(resultado.CookieRenovacionNueva!, resultado.CookieExpira!.Value);
        return Ok(new TokenRespuesta(resultado.TokenAcceso!, "Bearer", 900));
    }

    /// <summary>T-330.2 — exige Bearer y cookie, igual que el contrato.</summary>
    [HttpDelete("actual")]
    [Authorize]
    public async Task<IActionResult> CerrarAsync(CancellationToken ct)
    {
        var correlacionId = HttpContext.CorrelacionId();
        if (Request.Cookies.TryGetValue(NombreCookie, out var cookie) && !string.IsNullOrEmpty(cookie))
        {
            var partes = cookie.Split('.', 2);
            if (partes.Length == 2 && Guid.TryParse(partes[0], out var sesionId))
                await _cerrarSesion.EjecutarAsync(sesionId, correlacionId, ct);
        }
        BorrarCookie();
        return NoContent();
    }

    private void FijarCookie(string valor, DateTimeOffset expira) =>
        Response.Cookies.Append(NombreCookie, valor, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = RutaCookie,
            Expires = expira,
        });

    private void BorrarCookie() =>
        Response.Cookies.Delete(NombreCookie, new CookieOptions { Path = RutaCookie, Secure = true, HttpOnly = true, SameSite = SameSiteMode.Strict });
}
