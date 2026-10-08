// RedVital — identidad-service
// T-330.3 — Emisión del token de servicio de Donación (y, por el mismo
// mecanismo, del gateway y de Notificaciones — ADR-008 define tres clientes
// posibles, no solo Donación).
//
// Diferencia clave con el inicio de sesión de usuario: aquí no hay
// credencial de persona ni cookie de renovación — es credencial de máquina
// a máquina, verificada contra credencial_servicio.

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RedVital.Identidad.Dominio;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Aplicacion.CasosDeUso;

public record EmitirTokenServicioSolicitud(string Cliente, string Secreto);
public record EmitirTokenServicioResultado(bool Exitoso, string? TokenAcceso = null, int ExpiraEnSegundos = 900);

public class EmitirTokenServicio
{
    private static readonly string[] ClientesValidos = { "gateway", "donacion", "notificaciones" };

    private readonly IdentidadDbContext _contexto;
    private readonly PasswordHasher<CredencialServicio> _hasher = new();
    private readonly EmisorTokenAcceso _emisorToken;
    private readonly IRegistradorAuditoria _auditoria;

    public EmitirTokenServicio(IdentidadDbContext contexto, EmisorTokenAcceso emisorToken, IRegistradorAuditoria auditoria)
    {
        _contexto = contexto;
        _emisorToken = emisorToken;
        _auditoria = auditoria;
    }

    public async Task<EmitirTokenServicioResultado> EjecutarAsync(EmitirTokenServicioSolicitud solicitud, string correlacionId, CancellationToken ct = default)
    {
        if (!ClientesValidos.Contains(solicitud.Cliente))
            return new EmitirTokenServicioResultado(Exitoso: false);

        var credencial = await _contexto.CredencialesServicio
            .FirstOrDefaultAsync(c => c.Cliente == solicitud.Cliente, ct);

        var ahora = DateTimeOffset.UtcNow;

        if (credencial is null || !credencial.Activa)
        {
            await RegistrarAsync("sistema", solicitud.Cliente, "denegado", correlacionId, ahora, ct);
            return new EmitirTokenServicioResultado(Exitoso: false);
        }

        var verificacion = _hasher.VerifyHashedPassword(credencial, credencial.SecretoHash, solicitud.Secreto);
        if (verificacion == PasswordVerificationResult.Failed)
        {
            await RegistrarAsync("sistema", solicitud.Cliente, "denegado", correlacionId, ahora, ct);
            return new EmitirTokenServicioResultado(Exitoso: false);
        }

        var token = _emisorToken.EmitirParaServicio(solicitud.Cliente, ahora);

        await RegistrarAsync("sistema", solicitud.Cliente, "permitido", correlacionId, ahora, ct);

        return new EmitirTokenServicioResultado(Exitoso: true, TokenAcceso: token, ExpiraEnSegundos: 900);
    }

    private async Task RegistrarAsync(string actorTipo, string cliente, string resultado, string correlacionId, DateTimeOffset ahora, CancellationToken ct)
    {
        await _auditoria.RegistrarAsync(new RegistroAuditoriaIdent
        {
            Id = Guid.NewGuid(),
            ActorTipo = actorTipo,
            ActorId = cliente,
            Rol = "servicio",
            Operacion = "emision_token_servicio",
            RecursoTipo = "credencial_servicio",
            Resultado = resultado,
            CorrelacionId = correlacionId,
            OcurridoEn = ahora,
        }, ct);
    }
}
