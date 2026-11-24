// Identity service — capa Aplicacion. ADAPTA los puertos (ICuentaRepositorio, IHashContrasena,
// IAuditoria) a los que ya existen en develop; los nombres de aquí son placeholders.
using RedVital.Identidad.Dominio;

namespace RedVital.Identidad.Aplicacion;

public interface ICuentaRepositorio
{
    Task<bool> ExisteCorreoAsync(string correo, CancellationToken ct);
    Task<Guid> AgregarAsync(NuevaCuenta cuenta, string hashContrasena, Guid creadaPor, CancellationToken ct);
}
public interface IHashContrasena { string Hashear(string contrasena); }
public interface IAuditoria { Task RegistrarAsync(string accion, Guid actorId, string resultado, object? detalle, CancellationToken ct); }

public enum ResultadoCreacion { Creada, RolNoPermitido, FueraDeJurisdiccion, CorreoDuplicado, DatosInvalidos }

public sealed record RespuestaCreacion(ResultadoCreacion Resultado, Guid? Id = null);

public sealed class CrearCuentaCasoDeUso(ICuentaRepositorio cuentas, IHashContrasena hash, IAuditoria auditoria)
{
    public async Task<RespuestaCreacion> EjecutarAsync(
        Solicitante solicitante, NuevaCuenta nueva, string contrasena, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(nueva.Correo) || !nueva.Correo.Contains('@')
            || string.IsNullOrWhiteSpace(nueva.Nombre) || contrasena is null || contrasena.Length < 12)
            return new(ResultadoCreacion.DatosInvalidos);

        if (!PoliticaCreacionCuentas.PuedeCrearRol(solicitante.Rol, nueva.Rol))
            return await Denegar(solicitante, nueva, ResultadoCreacion.RolNoPermitido, ct);

        if (!PoliticaCreacionCuentas.EnJurisdiccion(solicitante, nueva))
            return await Denegar(solicitante, nueva, ResultadoCreacion.FueraDeJurisdiccion, ct);

        if (await cuentas.ExisteCorreoAsync(nueva.Correo, ct))
            return new(ResultadoCreacion.CorreoDuplicado);

        var id = await cuentas.AgregarAsync(nueva, hash.Hashear(contrasena), solicitante.CuentaId, ct);
        await auditoria.RegistrarAsync("cuenta.creada", solicitante.CuentaId, "ok", new { id, rol = nueva.Rol }, ct);
        return new(ResultadoCreacion.Creada, id);
    }

    private async Task<RespuestaCreacion> Denegar(Solicitante s, NuevaCuenta n, ResultadoCreacion r, CancellationToken ct)
    {
        await auditoria.RegistrarAsync("cuenta.creacion_denegada", s.CuentaId, r.ToString(), new { rolSolicitado = n.Rol }, ct);
        return new(r);
    }
}
