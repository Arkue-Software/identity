// Identity service — capa Api. Ajusta claims/nombres de ruta a tu configuración JWT real.
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RedVital.Identidad.Aplicacion;
using RedVital.Identidad.Dominio;

namespace RedVital.Identidad.Api;

public sealed record CrearCuentaPeticion(string Correo, string Nombre, RolCuenta Rol, string Contrasena,
                                         string? RutaTerritorial, Guid? BancoId);

[ApiController, Route("v1/cuentas"), Authorize]
public sealed class CuentasController(CrearCuentaCasoDeUso crear) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Crear([FromBody] CrearCuentaPeticion p, CancellationToken ct)
    {
        var solicitante = LeerSolicitante();
        var r = await crear.EjecutarAsync(solicitante,
            new NuevaCuenta(p.Correo, p.Nombre, p.Rol, p.RutaTerritorial, p.BancoId), p.Contrasena, ct);

        return r.Resultado switch
        {
            ResultadoCreacion.Creada => Created($"/v1/cuentas/{r.Id}", new { id = r.Id }),
            ResultadoCreacion.RolNoPermitido => Problema(403, "rol-no-permitido", "Tu rol no puede crear ese tipo de cuenta."),
            ResultadoCreacion.FueraDeJurisdiccion => Problema(403, "fuera-de-jurisdiccion", "La cuenta queda fuera de tu jurisdicción."),
            ResultadoCreacion.CorreoDuplicado => Problema(409, "correo-duplicado", "Ya existe una cuenta con ese correo."),
            _ => Problema(400, "datos-invalidos", "Revisa los datos (contraseña de mínimo 12 caracteres)."),
        };
    }

    private IActionResult Problema(int estado, string tipo, string detalle) =>
        StatusCode(estado, new { tipo, titulo = tipo, estado, detalle, correlacion_id = HttpContext.TraceIdentifier });

    // PLACEHOLDER: lee los claims reales que emite Identidad.
    private Solicitante LeerSolicitante() => new(
        Guid.Parse(User.FindFirst("sub")!.Value),
        Enum.Parse<RolCuenta>(User.FindFirst("rol")!.Value),
        User.FindFirst("ruta_territorial")?.Value,
        Guid.TryParse(User.FindFirst("banco_id")?.Value, out var b) ? b : null);
}
