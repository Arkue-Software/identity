// RedVital — identidad-service
// Alta de la cuenta de un donante registrado (RF-01, DD 15.4: POST /v1/donantes
// "crea la cuenta en Identidad y el perfil"). Solo la invoca el Servicio de
// Donación con su token de servicio, por /internal/v1/cuentas-donante; el
// gateway nunca enruta /internal.
//
// Idempotente por (cliente, clave): el reintento de un registro cuyo perfil no
// alcanzó a guardarse en Donación devuelve la misma cuenta. La huella no
// incluye la credencial: nunca se guarda ni se resume en otro lugar que el hash.

using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RedVital.Identidad.Dominio;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Aplicacion.CasosDeUso;

public record CrearCuentaDonanteSolicitud(string Correo, string Credencial, string Nombre);

public enum ResultadoCuenta { Creada, Reenvio, CorreoExistente, ClaveReutilizada, DatosInvalidos }

public record CrearCuentaDonanteResultado(ResultadoCuenta Resultado, Guid? UsuarioId = null);

public partial class CrearCuentaDonante
{
    private const string Operacion = "alta_cuenta_donante";
    private static readonly TimeSpan Vigencia = TimeSpan.FromHours(24);

    private readonly IdentidadDbContext _contexto;
    private readonly IRegistradorAuditoria _auditoria;
    private readonly PasswordHasher<Usuario> _hasher = new();

    public CrearCuentaDonante(IdentidadDbContext contexto, IRegistradorAuditoria auditoria)
    {
        _contexto = contexto;
        _auditoria = auditoria;
    }

    public async Task<CrearCuentaDonanteResultado> EjecutarAsync(CrearCuentaDonanteSolicitud s, string cliente,
        string clave, string correlacionId, CancellationToken ct = default)
    {
        var correo = s.Correo?.Trim().ToLowerInvariant() ?? "";
        var nombre = s.Nombre?.Trim() ?? "";
        if (!CorreoValido().IsMatch(correo) || correo.Length > 160 || nombre.Length is 0 or > 120
            || s.Credencial is null || s.Credencial.Length is < 10 or > 128
            || string.IsNullOrWhiteSpace(clave) || clave.Length > 64)
            return new(ResultadoCuenta.DatosInvalidos);

        var huella = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(correo + "\n" + nombre)));
        var previa = await _contexto.OperacionesIdempotentes.AsNoTracking()
            .FirstOrDefaultAsync(o => o.Sujeto == cliente && o.Clave == clave, ct);
        if (previa is not null)
            return previa.HuellaPeticion == huella && previa.Operacion == Operacion
                ? new(ResultadoCuenta.Reenvio, previa.RecursoId)
                : new(ResultadoCuenta.ClaveReutilizada);

        if (await _contexto.Usuarios.AnyAsync(u => u.Correo == correo, ct))
            return new(ResultadoCuenta.CorreoExistente);

        var ahora = DateTimeOffset.UtcNow;
        var usuario = new Usuario
        {
            Id = Guid.NewGuid(),
            Correo = correo,
            Nombre = nombre,
            CredencialHash = "",
            RolCodigo = "donante",
            Activo = true,
            CreadoEn = ahora,
            ActualizadoEn = ahora,
        };
        usuario.CredencialHash = _hasher.HashPassword(usuario, s.Credencial);
        _contexto.Usuarios.Add(usuario);
        _contexto.OperacionesIdempotentes.Add(new OperacionIdempotente
        {
            Sujeto = cliente, Clave = clave, Operacion = Operacion, HuellaPeticion = huella,
            RecursoId = usuario.Id, CreadoEn = ahora, ExpiraEn = ahora.Add(Vigencia),
        });

        try
        {
            await _contexto.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Carrera con otra petición: la misma clave o el mismo correo ya entraron.
            _contexto.ChangeTracker.Clear();
            var ganadora = await _contexto.OperacionesIdempotentes.AsNoTracking()
                .FirstOrDefaultAsync(o => o.Sujeto == cliente && o.Clave == clave, ct);
            return ganadora is not null && ganadora.HuellaPeticion == huella
                ? new(ResultadoCuenta.Reenvio, ganadora.RecursoId)
                : new(ResultadoCuenta.CorreoExistente);
        }

        await _auditoria.RegistrarAsync(new RegistroAuditoriaIdent
        {
            Id = Guid.NewGuid(),
            ActorTipo = "sistema",
            ActorId = cliente,
            Rol = "servicio",
            Operacion = Operacion,
            RecursoTipo = "usuario",
            RecursoId = usuario.Id,
            Resultado = "permitido",
            CorrelacionId = correlacionId,
            OcurridoEn = ahora,
        }, ct);

        return new(ResultadoCuenta.Creada, usuario.Id);
    }

    [GeneratedRegex(@"^[^\s@]+@[^\s@]+\.[^\s@]+$")]
    private static partial Regex CorreoValido();
}
