// RedVital — identidad-service
// T-330.1 — Renovación de sesión de 8 horas y rotación de credencial.
//
// La cookie de renovación (identidad-openapi.yaml: redvital_renovacion) trae
// "<sesionId>.<secretoEnClaro>". Cada renovación emite un token de acceso
// nuevo de 15 minutos Y sustituye el secreto de la cookie — rotación en cada
// uso, no solo al vencer. Esto es lo que permite detectar reutilización: si
// alguien presenta un secreto de renovación ya sustituido, es evidencia de
// que la cookie fue robada y usada por partida doble.

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RedVital.Identidad.Dominio;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Aplicacion.CasosDeUso;

public record RenovarSesionResultado(
    bool Exitoso,
    string? TokenAcceso = null,
    string? CookieRenovacionNueva = null,
    DateTimeOffset? CookieExpira = null,
    bool DetectadaReutilizacion = false);

public class RenovarSesion
{
    private readonly IdentidadDbContext _contexto;
    private readonly PasswordHasher<Usuario> _hasher = new();
    private readonly EmisorTokenAcceso _emisorToken;
    private readonly IRegistradorAuditoria _auditoria;

    public RenovarSesion(IdentidadDbContext contexto, EmisorTokenAcceso emisorToken, IRegistradorAuditoria auditoria)
    {
        _contexto = contexto;
        _emisorToken = emisorToken;
        _auditoria = auditoria;
    }

    public async Task<RenovarSesionResultado> EjecutarAsync(string cookieRenovacion, string correlacionId, CancellationToken ct = default)
    {
        var partes = cookieRenovacion.Split('.', 2);
        if (partes.Length != 2 || !Guid.TryParse(partes[0], out var sesionId))
            return new RenovarSesionResultado(Exitoso: false);

        var secretoPresentado = partes[1];

        var sesion = await _contexto.Sesiones
            .Include(s => s.Usuario!.Jurisdicciones)
            .FirstOrDefaultAsync(s => s.Id == sesionId, ct);

        var ahora = DateTimeOffset.UtcNow;

        if (sesion is null)
            return new RenovarSesionResultado(Exitoso: false);

        // --- Vigencia absoluta: ocho horas desde la emisión ORIGINAL, la
        // renovación nunca la extiende (DD, diccionario de datos de sesion).
        if (sesion.ExpiraEn <= ahora)
        {
            await RegistrarEventoAsync(sesion, "renovacion_rechazada_vencida", correlacionId, ahora, ct);
            return new RenovarSesionResultado(Exitoso: false);
        }

        if (sesion.RevocadaEn is not null)
        {
            await RegistrarEventoAsync(sesion, "renovacion_rechazada_revocada", correlacionId, ahora, ct);
            return new RenovarSesionResultado(Exitoso: false);
        }

        var verificacion = _hasher.VerifyHashedPassword(sesion.Usuario!, sesion.SecretoHash, secretoPresentado);
        if (verificacion == PasswordVerificationResult.Failed)
        {
            // Reutilización: el secreto presentado no coincide con el vigente.
            // Esto es más grave que una credencial inválida normal — revoca
            // TODA la sesión de inmediato, no solo rechaza esta renovación.
            sesion.RevocadaEn = ahora;
            sesion.MotivoRevocacion = "reutilizacion";
            await _contexto.SaveChangesAsync(ct);
            await RegistrarEventoAsync(sesion, "renovacion_reutilizacion_detectada", correlacionId, ahora, ct, resultado: "denegado");
            return new RenovarSesionResultado(Exitoso: false, DetectadaReutilizacion: true);
        }

        // --- Rotar el secreto (en cada renovación, no solo al vencer) ---
        var secretoNuevo = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        sesion.SecretoHash = _hasher.HashPassword(sesion.Usuario!, secretoNuevo);
        sesion.RenovadaEn = ahora;
        await _contexto.SaveChangesAsync(ct);

        var jurisdiccionVigente = ResolverJurisdiccion.Vigente(sesion.Usuario!, ahora);
        var tokenNuevo = _emisorToken.EmitirParaUsuario(sesion.Usuario!, jurisdiccionVigente, ahora);

        await RegistrarEventoAsync(sesion, "renovacion_sesion", correlacionId, ahora, ct);

        return new RenovarSesionResultado(
            Exitoso: true,
            TokenAcceso: tokenNuevo,
            CookieRenovacionNueva: $"{sesion.Id}.{secretoNuevo}",
            CookieExpira: sesion.ExpiraEn); // la cookie expone la MISMA expiración absoluta, no una nueva
    }

    private async Task RegistrarEventoAsync(Sesion sesion, string operacion, string correlacionId, DateTimeOffset ahora, CancellationToken ct, string resultado = "permitido")
    {
        await _auditoria.RegistrarAsync(new RegistroAuditoriaIdent
        {
            Id = Guid.NewGuid(),
            ActorTipo = "usuario",
            ActorId = sesion.UsuarioId.ToString(),
            Operacion = operacion,
            RecursoTipo = "sesion",
            RecursoId = sesion.Id,
            Resultado = resultado,
            CorrelacionId = correlacionId,
            OcurridoEn = ahora,
        }, ct);
    }
}
