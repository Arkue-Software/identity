// RedVital — identidad-service
// Rutas con prefijo /internal/: el gateway NUNCA las enruta (T-305.1). Solo
// son alcanzables dentro de la red de aplicación.
//
// T-330.3 → POST /internal/v1/sesiones/servicio   (token de servicio)
// T-330.4 → POST /internal/v1/auditoria/denegaciones (operación interna que
//           registra las denegaciones que entrega el gateway — la consume T-305.4)
// RF-01   → POST /internal/v1/cuentas-donante (alta de la cuenta del donante,
//           solo para el token de servicio de Donación)
//
// NOTA PARA SARA: estas dos rutas no están en identidad-openapi.yaml porque
// son internas. Conviene agregarlas a un contrato interno o a una sección
// "internal" del mismo archivo, para que no vivan solo en el código.

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

public record CuentaDonantePeticion(string Correo, string Credencial, string Nombre);
public record CuentaDonanteRespuesta(Guid UsuarioId);

[ApiController]
[Route("internal/v1")]
public class InternoController : ControllerBase
{
    private readonly EmitirTokenServicio _emitirTokenServicio;
    private readonly IRegistradorAuditoria _auditoria;
    private readonly CrearCuentaDonante _crearCuenta;

    public InternoController(EmitirTokenServicio emitirTokenServicio, IRegistradorAuditoria auditoria,
        CrearCuentaDonante crearCuenta)
    {
        _emitirTokenServicio = emitirTokenServicio;
        _auditoria = auditoria;
        _crearCuenta = crearCuenta;
    }

    /// <summary>
    /// RF-01. 201 con la cuenta nueva; 200 con la misma cuenta si es un reenvío;
    /// 409 si el correo ya tiene cuenta, sin decir nada más.
    /// </summary>
    [HttpPost("cuentas-donante")]
    [Authorize(Policy = "SoloDonacion")]
    public async Task<IActionResult> CrearCuentaDonanteAsync([FromBody] CuentaDonantePeticion peticion,
        [FromHeader(Name = "Idempotency-Key")] string? clave, CancellationToken ct)
    {
        var correlacionId = HttpContext.CorrelacionId();
        var r = await _crearCuenta.EjecutarAsync(new CrearCuentaDonanteSolicitud(peticion.Correo, peticion.Credencial,
            peticion.Nombre), "donacion", clave ?? "", correlacionId, ct);
        return r.Resultado switch
        {
            ResultadoCuenta.Creada => StatusCode(201, new CuentaDonanteRespuesta(r.UsuarioId!.Value)),
            ResultadoCuenta.Reenvio => Ok(new CuentaDonanteRespuesta(r.UsuarioId!.Value)),
            ResultadoCuenta.CorreoExistente => Problemas.Crear(409, "conflicto", "Conflicto",
                "No es posible crear la cuenta con estos datos.", correlacionId),
            ResultadoCuenta.ClaveReutilizada => Problemas.Crear(422, "clave-idempotencia-reutilizada",
                "Clave de idempotencia reutilizada", "La clave ya se usó con una petición distinta.", correlacionId),
            _ => Problemas.Crear(400, "validacion", "Datos inválidos", "Los datos de la cuenta no son válidos.", correlacionId),
        };
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
