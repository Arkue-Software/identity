// RedVital — identidad-service
// POST /v1/cuentas-donante → alta de la cuenta de un donante (RF-01). Es
// pública: quien se registra todavía no tiene sesión. El gateway le aplica un
// límite de peticiones por origen, como al inicio de sesión.

using Microsoft.AspNetCore.Mvc;
using RedVital.Identidad.Api.Soporte;
using RedVital.Identidad.Aplicacion.CasosDeUso;

namespace RedVital.Identidad.Api.Controllers;

public record CuentaDonantePeticion(string Correo, string Credencial, string Nombre);
public record CuentaDonanteRespuesta(Guid UsuarioId);

[ApiController]
[Route("v1/cuentas-donante")]
public class CuentasDonanteController : ControllerBase
{
    /// <summary>Sujeto de la idempotencia: la petición no tiene otro.</summary>
    private const string Cliente = "registro-publico";

    private readonly CrearCuentaDonante _crearCuenta;

    public CuentasDonanteController(CrearCuentaDonante crearCuenta) => _crearCuenta = crearCuenta;

    /// <summary>
    /// 201 con la cuenta nueva; 200 con la misma cuenta si es un reenvío;
    /// 409 si el correo ya tiene cuenta, sin decir nada más.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> CrearAsync([FromBody] CuentaDonantePeticion peticion,
        [FromHeader(Name = "Idempotency-Key")] string? clave, CancellationToken ct)
    {
        var correlacionId = HttpContext.CorrelacionId();
        var r = await _crearCuenta.EjecutarAsync(new CrearCuentaDonanteSolicitud(peticion.Correo, peticion.Credencial,
            peticion.Nombre), Cliente, clave ?? "", correlacionId, ct);
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
}
