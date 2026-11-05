// RedVital — identidad-service
// T-330.2 — Término de sesión e invalidación de renovación (RF-24).
//
// "Cuando un usuario cierre su sesión o esta alcance su vigencia máxima, el
// sistema deberá revocarla y exigir de nuevo las credenciales para toda
// operación que requiera sesión." El segundo caso (vigencia máxima) no
// necesita código aquí — ya lo cubre la verificación de ExpiraEn en
// RenovarSesion; esta clase cubre el cierre EXPLÍCITO (RF-24, primer caso).

using Microsoft.EntityFrameworkCore;
using RedVital.Identidad.Dominio;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Aplicacion.CasosDeUso;

public class CerrarSesion
{
    private readonly IdentidadDbContext _contexto;
    private readonly IRegistradorAuditoria _auditoria;

    public CerrarSesion(IdentidadDbContext contexto, IRegistradorAuditoria auditoria)
    {
        _contexto = contexto;
        _auditoria = auditoria;
    }

    /// <returns>
    /// true si cerró algo real. false si la sesión no existía o ya estaba
    /// cerrada — el controlador responde 204 en los dos casos por igual
    /// (cerrar una sesión que ya no existe no es un error desde la
    /// perspectiva del cliente).
    /// </returns>
    public async Task<bool> EjecutarAsync(Guid sesionId, string correlacionId, CancellationToken ct = default)
    {
        var sesion = await _contexto.Sesiones.FirstOrDefaultAsync(s => s.Id == sesionId, ct);

        if (sesion is null || sesion.RevocadaEn is not null)
            return false;

        var ahora = DateTimeOffset.UtcNow;
        sesion.RevocadaEn = ahora;
        sesion.MotivoRevocacion = "cierre";
        await _contexto.SaveChangesAsync(ct);

        await _auditoria.RegistrarAsync(new RegistroAuditoriaIdent
        {
            Id = Guid.NewGuid(),
            ActorTipo = "usuario",
            ActorId = sesion.UsuarioId.ToString(),
            Operacion = "cierre_sesion",
            RecursoTipo = "sesion",
            RecursoId = sesion.Id,
            Resultado = "permitido",
            CorrelacionId = correlacionId,
            OcurridoEn = ahora,
        }, ct);

        return true;
    }

    /// <summary>
    /// Complemento operativo de T-330.2: desactivar una cuenta revoca TODAS
    /// sus sesiones activas (ADR-008: "la desactivación revoca todas las
    /// sesiones del usuario"). No es parte del contrato de RF-24 en sentido
    /// estricto, pero es la misma mecánica y pertenece a la misma tarea.
    /// </summary>
    public async Task RevocarTodasPorDesactivacionAsync(Guid usuarioId, string correlacionId, CancellationToken ct = default)
    {
        var ahora = DateTimeOffset.UtcNow;
        var sesionesActivas = await _contexto.Sesiones
            .Where(s => s.UsuarioId == usuarioId && s.RevocadaEn == null && s.ExpiraEn > ahora)
            .ToListAsync(ct);

        foreach (var sesion in sesionesActivas)
        {
            sesion.RevocadaEn = ahora;
            sesion.MotivoRevocacion = "desactivacion";
        }
        await _contexto.SaveChangesAsync(ct);

        foreach (var sesion in sesionesActivas)
        {
            await _auditoria.RegistrarAsync(new RegistroAuditoriaIdent
            {
                Id = Guid.NewGuid(),
                ActorTipo = "sistema",
                ActorId = "identidad-service",
                Operacion = "revocacion_por_desactivacion",
                RecursoTipo = "sesion",
                RecursoId = sesion.Id,
                Resultado = "permitido",
                CorrelacionId = correlacionId,
                OcurridoEn = ahora,
            }, ct);
        }
    }
}
