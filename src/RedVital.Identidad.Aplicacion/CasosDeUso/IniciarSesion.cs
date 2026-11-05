// RedVital — identidad-service
// T-304.2 — Verificar credenciales en inicio de sesión.
// T-304.3 — Emitir token de acceso RS256 de 15 minutos.
//
// Van en el mismo caso de uso porque el contrato real (identidad-openapi.yaml,
// POST /v1/sesiones) responde las dos cosas en una sola llamada: valida la
// credencial Y devuelve el token de acceso, además de iniciar la sesión de
// renovación de 8 horas (RF-23).

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RedVital.Identidad.Dominio;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Aplicacion.CasosDeUso;

public record IniciarSesionSolicitud(string Correo, string Credencial, string? Origen);

public record IniciarSesionResultado(
    bool Exitoso,
    string? TokenAcceso = null,
    int ExpiraEnSegundos = 900,
    string? CookieRenovacion = null,
    DateTimeOffset? CookieExpira = null);

public class IniciarSesion
{
    private readonly IdentidadDbContext _contexto;
    private readonly PasswordHasher<Usuario> _hasher = new();
    private readonly EmisorTokenAcceso _emisorToken;
    private readonly IRegistradorAuditoria _auditoria;

    public IniciarSesion(IdentidadDbContext contexto, EmisorTokenAcceso emisorToken, IRegistradorAuditoria auditoria)
    {
        _contexto = contexto;
        _emisorToken = emisorToken;
        _auditoria = auditoria;
    }
    public async Task<IniciarSesionResultado> EjecutarAsync(IniciarSesionSolicitud solicitud, string correlacionId, CancellationToken ct = default)
    {
        var usuario = await _contexto.Usuarios
            .Include(u => u.Jurisdicciones)
            .FirstOrDefaultAsync(u => u.Correo == solicitud.Correo, ct);

        // La respuesta ante credenciales incorrectas NUNCA indica cuál de los
        // dos datos falló (SRS V3, nota de RF-23/RF-24) — por eso el mismo
        // mensaje genérico cubre "no existe el usuario" y "la credencial no
        // coincide". No separes estos dos casos en el controlador tampoco.
        if (usuario is null || !usuario.Activo)
        {
            await RegistrarIntentoFallidoAsync(solicitud.Correo, correlacionId, solicitud.Origen, ct);
            return new IniciarSesionResultado(Exitoso: false);
        }

        var verificacion = _hasher.VerifyHashedPassword(usuario, usuario.CredencialHash, solicitud.Credencial);
        if (verificacion == PasswordVerificationResult.Failed)
        {
            await RegistrarIntentoFallidoAsync(solicitud.Correo, correlacionId, solicitud.Origen, ct, usuario.Id.ToString());
            return new IniciarSesionResultado(Exitoso: false);
        }

        var ahora = DateTimeOffset.UtcNow;

        // --- Sesión de renovación (8 horas, con estado — RF-23) ---
        var secretoRenovacion = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
        var sesion = new Sesion
        {
            Id = Guid.NewGuid(),
            UsuarioId = usuario.Id,
            SecretoHash = _hasher.HashPassword(usuario, secretoRenovacion),
            EmitidaEn = ahora,
            ExpiraEn = ahora.AddHours(8),
            Origen = solicitud.Origen,
        };
        _contexto.Sesiones.Add(sesion);

        usuario.UltimoAccesoEn = ahora;
        await _contexto.SaveChangesAsync(ct);

        // --- Token de acceso (15 minutos, sin estado — ADR-008) ---
        var token = _emisorToken.EmitirParaUsuario(usuario, ResolverJurisdiccion.Vigente(usuario, ahora), ahora);

        await _auditoria.RegistrarAsync(new RegistroAuditoriaIdent
        {
            Id = Guid.NewGuid(),
            ActorTipo = "usuario",
            ActorId = usuario.Id.ToString(),
            Rol = usuario.RolCodigo,
            Operacion = "inicio_sesion",
            RecursoTipo = "sesion",
            RecursoId = sesion.Id,
            Resultado = "permitido",
            CorrelacionId = correlacionId,
            Origen = solicitud.Origen,
            OcurridoEn = ahora,
        }, ct);

        return new IniciarSesionResultado(
            Exitoso: true,
            TokenAcceso: token,
            ExpiraEnSegundos: 900,
            // El valor de cookie es "<sesionId>.<secretoEnClaro>" — el
            // controlador lo fija como cookie HttpOnly/Secure/SameSite=Strict
            // limitada a /v1/sesiones, nunca lo devuelve en el cuerpo JSON.
            CookieRenovacion: $"{sesion.Id}.{secretoRenovacion}",
            CookieExpira: sesion.ExpiraEn);
    }

    private async Task RegistrarIntentoFallidoAsync(string correo, string correlacionId, string? origen, CancellationToken ct, string? actorId = null)
    {
        await _auditoria.RegistrarAsync(new RegistroAuditoriaIdent
        {
            Id = Guid.NewGuid(),
            ActorTipo = actorId is null ? "anonimo" : "usuario",
            ActorId = actorId,
            Operacion = "inicio_sesion",
            RecursoTipo = "sesion",
            Resultado = "denegado",
            CorrelacionId = correlacionId,
            Origen = origen,
            OcurridoEn = DateTimeOffset.UtcNow,
        }, ct);
    }
}
