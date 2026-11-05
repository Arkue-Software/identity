// RedVital — identidad-service
// Interfaces (puertos) que Infraestructura implementa y Aplicación consume.
// Viven en Dominio, la única capa sin dependencias, para evitar que
// Aplicación e Infraestructura terminen referenciándose la una a la otra.

using Microsoft.IdentityModel.Tokens;

namespace RedVital.Identidad.Dominio;

public interface IProveedorLlaveFirma
{
    (string Kid, SecurityKey ClavePrivada) ObtenerLlaveVigente();
}

public interface IRegistradorAuditoria
{
    Task RegistrarAsync(RegistroAuditoriaIdent registro, CancellationToken ct = default);
}
