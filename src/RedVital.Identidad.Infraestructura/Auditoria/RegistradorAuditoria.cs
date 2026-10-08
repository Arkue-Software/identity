// RedVital — identidad-service
// Implementación de IRegistradorAuditoria. No expone ningún método de
// actualización o borrado a propósito — solo Insertar.

using RedVital.Identidad.Dominio;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Infraestructura.Auditoria;

public class RegistradorAuditoria : IRegistradorAuditoria
{
    private readonly IdentidadDbContext _contexto;

    public RegistradorAuditoria(IdentidadDbContext contexto) => _contexto = contexto;

    public async Task RegistrarAsync(RegistroAuditoriaIdent registro, CancellationToken ct = default)
    {
        _contexto.RegistroAuditoriaIdent.Add(registro);
        await _contexto.SaveChangesAsync(ct);
    }
}
