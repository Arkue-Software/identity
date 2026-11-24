// RedVital — identidad-service
// Implementación de IRegistradorAuditoria. No expone ningún método de
// actualización o borrado a propósito — solo Insertar.
//
// Cada registro sale también a Kafka (EV-10, audit.recorded) para la bitácora
// del Servicio Institucional: el evento entra a la bandeja de salida en la
// misma transacción que el registro, así que nunca hay uno sin el otro.

using System.Text.Json;
using RedVital.Identidad.Dominio;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Infraestructura.Auditoria;

public class RegistradorAuditoria : IRegistradorAuditoria
{
    public const string Tema = "redvital.identidad.audit-recorded.v1";
    public const string Tipo = "audit.recorded";

    private static readonly JsonSerializerOptions Contrato = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower };

    private readonly IdentidadDbContext _contexto;

    public RegistradorAuditoria(IdentidadDbContext contexto) => _contexto = contexto;

    public async Task RegistrarAsync(RegistroAuditoriaIdent registro, CancellationToken ct = default)
    {
        _contexto.RegistroAuditoriaIdent.Add(registro);
        _contexto.EventosSalida.Add(new EventoSalida
        {
            Id = Guid.NewGuid(),
            Tipo = Tipo,
            VersionEsquema = 1,
            Tema = Tema,
            // Por correlación: los registros de una misma operación quedan en orden.
            Clave = registro.CorrelacionId,
            Carga = JsonSerializer.Serialize(new
            {
                registro.Id, registro.ActorTipo, registro.ActorId, registro.Rol, registro.JurisdiccionSolicitada,
                registro.Operacion, registro.RecursoTipo, registro.RecursoId, registro.Resultado,
                registro.CorrelacionId, registro.Origen, registro.OcurridoEn,
            }, Contrato),
            CorrelacionId = registro.CorrelacionId,
            CreadoEn = DateTimeOffset.UtcNow,
        });
        await _contexto.SaveChangesAsync(ct);
    }
}
