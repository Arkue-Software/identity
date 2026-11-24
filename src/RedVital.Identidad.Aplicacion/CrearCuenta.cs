using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using RedVital.Identidad.Aplicacion.CasosDeUso;
using RedVital.Identidad.Dominio;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Aplicacion;

public enum ResultadoCreacion { Creada, RolNoPermitido, FueraDeJurisdiccion, CorreoDuplicado, DatosInvalidos }

public sealed record RespuestaCreacion(ResultadoCreacion Resultado, Guid? Id = null);

public sealed class CrearCuentaCasoDeUso
{
    private readonly IdentidadDbContext _contexto;
    private readonly IRegistradorAuditoria _auditoria;
    private readonly PasswordHasher<Usuario> _hasher = new();

    public CrearCuentaCasoDeUso(IdentidadDbContext contexto, IRegistradorAuditoria auditoria)
    {
        _contexto = contexto;
        _auditoria = auditoria;
    }

    public async Task<RespuestaCreacion> EjecutarAsync(
        Solicitante solicitante, NuevaCuenta nueva, string contrasena, string correlacionId, CancellationToken ct = default)
    {
        var correo = nueva.Correo?.Trim().ToLowerInvariant() ?? "";
        var nombre = nueva.Nombre?.Trim() ?? "";
        var rutaNorm = PoliticaCreacionCuentas.NormalizarRuta(nueva.RutaTerritorial);
        var cuentaNorm = nueva with { Correo = correo, Nombre = nombre, RutaTerritorial = rutaNorm };

        if (string.IsNullOrWhiteSpace(correo) || !correo.Contains('@') || correo.Length > 160
            || string.IsNullOrWhiteSpace(nombre) || nombre.Length > 120
            || string.IsNullOrWhiteSpace(contrasena) || contrasena.Length < 12 || contrasena.Length > 128)
            return new(ResultadoCreacion.DatosInvalidos);

        // Valida jurisdicción obligatoria según el rol a crear
        if (cuentaNorm.Rol == RolCuenta.U5 && rutaNorm is null)
            return new(ResultadoCreacion.DatosInvalidos);
        if (cuentaNorm.Rol is RolCuenta.U4 or RolCuenta.U3 && cuentaNorm.BancoId is null)
            return new(ResultadoCreacion.DatosInvalidos);

        if (!PoliticaCreacionCuentas.PuedeCrearRol(solicitante.Rol, cuentaNorm.Rol))
            return await DenegarAsync(solicitante, cuentaNorm, ResultadoCreacion.RolNoPermitido, correlacionId, ct);

        if (!PoliticaCreacionCuentas.EnJurisdiccion(solicitante, cuentaNorm))
            return await DenegarAsync(solicitante, cuentaNorm, ResultadoCreacion.FueraDeJurisdiccion, correlacionId, ct);

        if (await _contexto.Usuarios.AnyAsync(u => u.Correo == correo, ct))
            return new(ResultadoCreacion.CorreoDuplicado);

        var ahora = DateTimeOffset.UtcNow;
        var rolCodigoBd = MapearRolABd(cuentaNorm.Rol);

        var usuario = new Usuario
        {
            Id = Guid.NewGuid(),
            Correo = correo,
            Nombre = nombre,
            CredencialHash = "",
            RolCodigo = rolCodigoBd,
            Activo = true,
            CreadoEn = ahora,
            ActualizadoEn = ahora,
        };
        usuario.CredencialHash = _hasher.HashPassword(usuario, contrasena);
        _contexto.Usuarios.Add(usuario);

        if (cuentaNorm.Rol == RolCuenta.U5 && rutaNorm is not null)
        {
            var codigoTerritorio = rutaNorm.Split('/', StringSplitOptions.RemoveEmptyEntries).Last();
            _contexto.UsuarioJurisdicciones.Add(new UsuarioJurisdiccion
            {
                Id = Guid.NewGuid(),
                UsuarioId = usuario.Id,
                Ambito = "territorio",
                TerritorioCodigo = codigoTerritorio,
                TerritorioRuta = rutaNorm,
                AsignadaPor = solicitante.CuentaId,
                VigenteDesde = ahora,
            });
        }
        else if (cuentaNorm.Rol is RolCuenta.U4 or RolCuenta.U3 && cuentaNorm.BancoId is { } bancoId)
        {
            _contexto.UsuarioJurisdicciones.Add(new UsuarioJurisdiccion
            {
                Id = Guid.NewGuid(),
                UsuarioId = usuario.Id,
                Ambito = "institucion",
                InstitucionId = bancoId,
                AsignadaPor = solicitante.CuentaId,
                VigenteDesde = ahora,
            });
        }

        try
        {
            await _contexto.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            _contexto.ChangeTracker.Clear();
            return new(ResultadoCreacion.CorreoDuplicado);
        }

        await _auditoria.RegistrarAsync(new RegistroAuditoriaIdent
        {
            Id = Guid.NewGuid(),
            ActorTipo = "usuario",
            ActorId = solicitante.CuentaId.ToString(),
            Rol = MapearRolABd(solicitante.Rol),
            JurisdiccionSolicitada = rutaNorm ?? cuentaNorm.BancoId?.ToString(),
            Operacion = "crear_cuenta",
            RecursoTipo = "usuario",
            RecursoId = usuario.Id,
            Resultado = "permitido",
            CorrelacionId = correlacionId,
            OcurridoEn = ahora,
        }, ct);

        return new(ResultadoCreacion.Creada, usuario.Id);
    }

    private async Task<RespuestaCreacion> DenegarAsync(
        Solicitante s, NuevaCuenta n, ResultadoCreacion motivo, string correlacionId, CancellationToken ct)
    {
        await _auditoria.RegistrarAsync(new RegistroAuditoriaIdent
        {
            Id = Guid.NewGuid(),
            ActorTipo = "usuario",
            ActorId = s.CuentaId.ToString(),
            Rol = MapearRolABd(s.Rol),
            JurisdiccionSolicitada = n.RutaTerritorial ?? n.BancoId?.ToString(),
            Operacion = "crear_cuenta",
            RecursoTipo = "usuario",
            Resultado = "denegado",
            CorrelacionId = correlacionId,
            OcurridoEn = DateTimeOffset.UtcNow,
        }, ct);
        return new(motivo);
    }

    public static string MapearRolABd(RolCuenta rol) => rol switch
    {
        RolCuenta.U2 => "donante",
        RolCuenta.U3 => "operador",
        RolCuenta.U4 => "admin_banco",
        RolCuenta.U5 => "coordinador",
        RolCuenta.U6 => "admin_nacional",
        RolCuenta.U7 => "auditor",
        _ => throw new ArgumentOutOfRangeException(nameof(rol)),
    };

    public static bool TryParseRol(string? valor, out RolCuenta rol)
    {
        rol = valor?.Trim().ToLowerInvariant() switch
        {
            "u1" => RolCuenta.U1,
            "u2" or "donante" => RolCuenta.U2,
            "u3" or "operador" => RolCuenta.U3,
            "u4" or "admin_banco" => RolCuenta.U4,
            "u5" or "coordinador" => RolCuenta.U5,
            "u6" or "admin_nacional" => RolCuenta.U6,
            "u7" or "auditor" => RolCuenta.U7,
            _ => default,
        };
        return rol != default;
    }
}
