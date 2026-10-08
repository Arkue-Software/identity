// RedVital — identidad-service
// GET /v1/usuarios/me → datos de la propia cuenta (DD 15.1).

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RedVital.Identidad.Api.Soporte;
using RedVital.Identidad.Aplicacion.CasosDeUso;

namespace RedVital.Identidad.Api.Controllers;

[ApiController]
[Route("v1/usuarios")]
public class UsuariosController : ControllerBase
{
    private readonly ConsultarUsuarioActual _consultar;

    public UsuariosController(ConsultarUsuarioActual consultar) => _consultar = consultar;

    [HttpGet("me")]
    [Authorize]
    public async Task<IActionResult> ActualAsync(CancellationToken ct)
    {
        var correlacionId = HttpContext.CorrelacionId();
        // Un token de servicio no representa a una persona.
        if (User.FindFirst("role")?.Value == "servicio" || !Guid.TryParse(User.FindFirst("sub")?.Value, out var id))
            return Problemas.OperacionNoPermitida(correlacionId);

        var vista = await _consultar.EjecutarAsync(id, ct);
        return vista is null
            ? Problemas.SesionInvalida(correlacionId, "La cuenta no existe o está inactiva.")
            : Ok(vista);
    }
}
