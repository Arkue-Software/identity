// RedVital — identidad-service
// Rutas con prefijo /internal/: el gateway NUNCA las enruta (T-305.1). Solo
// son alcanzables dentro de la red de aplicación.
//
// T-330.3 → POST /internal/v1/sesiones/servicio   (token de servicio del gateway)
// T-330.4 → POST /internal/v1/auditoria/denegaciones (registra las denegaciones
//           que entrega el gateway — la consume T-305.4)
//
// Ningún otro servicio llama a Identidad: entre servicios todo pasa por Kafka.

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RedVital.Identidad.Api.Soporte;
using RedVital.Identidad.Aplicacion.CasosDeUso;
using RedVital.Identidad.Dominio;

namespace RedVital.Identidad.Api.Controllers;

public record TokenServicioPeticion(string Cliente, string Secreto);

/// <summary>Lo que el gateway envía por cada acceso que rechaza.</summary>
public record DenegacionPeticion(
    string? ActorId,
    string? Rol,
    string? JurisdiccionSolicitada,
    string Operacion,
    string RecursoTipo,
    string CorrelacionId,
    string? Origen,
    DateTimeOffset OcurridoEn);

[ApiController]
[Route("internal/v1")]
public class InternoController : ControllerBase
{
    private readonly EmitirTokenServicio _emitirTokenServicio;
    private readonly IRegistradorAuditoria _auditoria;

    public InternoController(EmitirTokenServicio emitirTokenServicio, IRegistradorAuditoria auditoria)
    {
        _emitirTokenServicio = emitirTokenServicio;
        _auditoria = auditoria;
    }

    /// <summary>T-330.3</summary>
    [HttpPost("sesiones/servicio")]
    public async Task<IActionResult> EmitirTokenServicioAsync([FromBody] TokenServicioPeticion peticion, CancellationToken ct)
    {
        var correlacionId = HttpContext.CorrelacionId();
        var resultado = await _emitirTokenServicio.EjecutarAsync(
            new EmitirTokenServicioSolicitud(peticion.Cliente, peticion.Secreto), correlacionId, ct);

        if (!resultado.Exitoso)
            return Problemas.SesionInvalida(correlacionId, "Credencial de servicio inválida.");

        return Ok(new TokenRespuesta(resultado.TokenAcceso!, "Bearer", resultado.ExpiraEnSegundos));
    }

    /// <summary>
    /// T-330.4 — solo el gateway puede escribir aquí (token de servicio con
    /// sub = "gateway"). Nunca se guarda el dato al que se intentó acceder.
    /// </summary>
    [HttpPost("auditoria/denegaciones")]
    [Authorize(Policy = "SoloGateway")]
    public async Task<IActionResult> RegistrarDenegacionAsync([FromBody] DenegacionPeticion peticion, CancellationToken ct)
    {
        // Token ausente o inválido → nadie identificable → "anonimo", con
        // actor_id NULO (la base rechaza un anónimo con actor, aunque sea "").
        var actorId = string.IsNullOrWhiteSpace(peticion.ActorId) ? null : peticion.ActorId;
        await _auditoria.RegistrarAsync(new RegistroAuditoriaIdent
        {
            Id = Guid.NewGuid(),
            ActorTipo = actorId is null ? "anonimo" : "usuario",
            ActorId = actorId,
            Rol = peticion.Rol,
            JurisdiccionSolicitada = peticion.JurisdiccionSolicitada,
            Operacion = peticion.Operacion,
            RecursoTipo = peticion.RecursoTipo,
            Resultado = "denegado",
            CorrelacionId = peticion.CorrelacionId,
            Origen = peticion.Origen,
            OcurridoEn = peticion.OcurridoEn,
        }, ct);

        return Accepted();
    }
}
