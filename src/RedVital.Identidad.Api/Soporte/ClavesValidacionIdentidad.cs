// RedVital — identidad-service
// Claves públicas con las que este mismo servicio valida los tokens que
// recibe (EC-03: cada servicio revalida, no confía en el gateway). Se leen
// de llave_firma — la misma fuente que publica el JWKS de T-304.4.
//
// Caché de 5 minutos: es seguro porque ADR-008 publica la clave nueva diez
// minutos ANTES de empezar a firmar con ella, así que ningún token nuevo
// llega antes de que la caché ya conozca su clave.

using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Api.Soporte;

public class ClavesValidacionIdentidad
{
    private readonly IServiceScopeFactory _scopes;
    private readonly object _candado = new();
    private List<SecurityKey> _cache = new();
    private DateTimeOffset _vence = DateTimeOffset.MinValue;

    public ClavesValidacionIdentidad(IServiceScopeFactory scopes) => _scopes = scopes;

    public IEnumerable<SecurityKey> Obtener()
    {
        lock (_candado)
        {
            var ahora = DateTimeOffset.UtcNow;
            if (ahora < _vence) return _cache;

            using var scope = _scopes.CreateScope();
            var contexto = scope.ServiceProvider.GetRequiredService<IdentidadDbContext>();

            _cache = contexto.LlavesFirma
                .Where(k => k.RetiradaEn == null || k.RetiradaEn > ahora)
                .AsEnumerable()
                .Select(k =>
                {
                    var rsa = RSA.Create();
                    rsa.ImportFromPem(k.ClavePublicaPem);
                    return (SecurityKey)new RsaSecurityKey(rsa) { KeyId = k.Kid };
                })
                .ToList();

            _vence = ahora.AddMinutes(5);
            return _cache;
        }
    }
}
