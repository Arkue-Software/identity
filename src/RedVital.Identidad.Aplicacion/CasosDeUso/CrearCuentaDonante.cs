// RedVital — identidad-service
// Alta de la cuenta de un donante (RF-01). La pide la propia persona desde la
// web por POST /v1/cuentas-donante, sin sesión; con la sesión que abre después
// crea su perfil de donante en el Servicio de Donación. Ningún servicio llama a
// otro para esto, y la credencial nunca sale de Identidad.
//
// Idempotente por (cliente, clave): reenviar el mismo formulario con la misma
// Idempotency-Key devuelve la misma cuenta. La huella no incluye la credencial:
// nunca se guarda ni se resume en otro lugar que el hash.

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
            || !CredencialAceptable(s.Credencial)
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
            ActorTipo = "anonimo",
            Operacion = Operacion,
            RecursoTipo = "usuario",
            RecursoId = usuario.Id,
            Resultado = "permitido",
            CorrelacionId = correlacionId,
            OcurridoEn = ahora,
        }, ct);

        return new(ResultadoCuenta.Creada, usuario.Id);
    }

    /// <summary>La misma regla que muestra la web: de 10 a 128 caracteres, con letras y números.</summary>
    private static bool CredencialAceptable(string? credencial) =>
        credencial is { Length: >= 10 and <= 128 } && credencial.Any(char.IsLetter) && credencial.Any(char.IsDigit);

    [GeneratedRegex(@"^[^\s@]+@[^\s@]+\.[^\s@]+$")]
    private static partial Regex CorreoValido();
}
