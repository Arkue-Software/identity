// RedVital — identidad-service
// GET /v1/usuarios/me (DD 15.1): rol, nombre si lo tiene y ámbitos vigentes.
// Lo que la interfaz necesita para presentar la sesión sin leer el token.
// Nunca devuelve resúmenes de credencial.

using Microsoft.EntityFrameworkCore;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Aplicacion.CasosDeUso;

public record AmbitoVista(string Ambito, string? TerritorioCodigo, string? TerritorioRuta, Guid? InstitucionId);

public record UsuarioActualVista(Guid Id, string Correo, string? Nombre, string Rol, IReadOnlyList<AmbitoVista> Ambitos);

public class ConsultarUsuarioActual
{
    private readonly IdentidadDbContext _contexto;

    public ConsultarUsuarioActual(IdentidadDbContext contexto) => _contexto = contexto;

    public async Task<UsuarioActualVista?> EjecutarAsync(Guid usuarioId, CancellationToken ct = default)
    {
        var ahora = DateTimeOffset.UtcNow;
        var usuario = await _contexto.Usuarios.AsNoTracking()
            .Include(u => u.Jurisdicciones)
            .FirstOrDefaultAsync(u => u.Id == usuarioId && u.Activo, ct);
        if (usuario is null) return null;

        var ambitos = usuario.Jurisdicciones
            .Where(j => j.VigenteDesde <= ahora && (j.VigenteHasta is null || j.VigenteHasta > ahora))
            .OrderByDescending(j => j.VigenteDesde)
            .Select(j => new AmbitoVista(j.Ambito, j.TerritorioCodigo, j.TerritorioRuta, j.InstitucionId))
            .ToList();
        return new UsuarioActualVista(usuario.Id, usuario.Correo, usuario.Nombre, usuario.RolCodigo, ambitos);
    }
}
