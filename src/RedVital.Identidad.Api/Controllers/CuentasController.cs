using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using RedVital.Identidad.Api.Soporte;
using RedVital.Identidad.Aplicacion;
using RedVital.Identidad.Dominio;

namespace RedVital.Identidad.Api.Controllers;

public sealed record CrearCuentaPeticion(
    string Correo,
    string Nombre,
    string Rol,
    string Contrasena,
    string? RutaTerritorial,
    Guid? BancoId);

[ApiController, Route("v1/cuentas"), Authorize]
public sealed class CuentasController(CrearCuentaCasoDeUso crear) : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> Crear([FromBody] CrearCuentaPeticion p, CancellationToken ct)
    {
        var correlacionId = HttpContext.CorrelacionId();
        var solicitante = LeerSolicitante();
        if (solicitante is null)
            return Problemas.OperacionNoPermitida(correlacionId);

        if (!CrearCuentaCasoDeUso.TryParseRol(p.Rol, out var rolObjetivo))
            return Problema(400, "datos-invalidos", "El rol indicado no es válido.", correlacionId);

        var r = await crear.EjecutarAsync(
            solicitante,
            new NuevaCuenta(p.Correo, p.Nombre, rolObjetivo, p.RutaTerritorial, p.BancoId),
            p.Contrasena,
            correlacionId,
            ct);

        return r.Resultado switch
        {
            ResultadoCreacion.Creada => Created($"/v1/cuentas/{r.Id}", new { id = r.Id }),
            ResultadoCreacion.RolNoPermitido => Problema(403, "rol-no-permitido", "Tu rol no puede crear ese tipo de cuenta.", correlacionId),
            ResultadoCreacion.FueraDeJurisdiccion => Problema(403, "fuera-de-jurisdiccion", "La cuenta queda fuera de tu jurisdicción.", correlacionId),
            ResultadoCreacion.CorreoDuplicado => Problema(409, "correo-duplicado", "Ya existe una cuenta con ese correo.", correlacionId),
            _ => Problema(400, "datos-invalidos", "Revisa los datos (contraseña de mín. 12 caracteres y territorio/banco según el rol).", correlacionId),
        };
    }

    private IActionResult Problema(int estado, string tipo, string detalle, string correlacionId) =>
        StatusCode(estado, new { tipo, titulo = tipo, estado, detalle, correlacion_id = correlacionId });

    private Solicitante? LeerSolicitante()
    {
        var sub = User.FindFirst("sub")?.Value;
        var roleClaim = User.FindFirst("role")?.Value;
        if (!Guid.TryParse(sub, out var cuentaId) || !CrearCuentaCasoDeUso.TryParseRol(roleClaim, out var rol))
            return null;

        var juris = User.FindFirst("jurisdiction")?.Value ?? "";
        string? ruta = null;
        Guid? bancoId = null;

        if (juris.StartsWith("territorio:", StringComparison.Ordinal))
            ruta = juris["territorio:".Length..];
        else if (juris.StartsWith("institucion:", StringComparison.Ordinal)
                 && Guid.TryParse(juris["institucion:".Length..], out var b))
            bancoId = b;

        return new Solicitante(cuentaId, rol, ruta, bancoId);
    }
}
