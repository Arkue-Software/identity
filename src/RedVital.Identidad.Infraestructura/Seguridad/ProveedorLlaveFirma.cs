// RedVital — identidad-service
// Dos implementaciones de IProveedorLlaveFirma, seleccionadas por ambiente
// en Program.cs. Esta separación es la que hace cumplir, a nivel de código y
// no solo de documentación, que la llave de prueba de T-303.1 JAMÁS pueda
// usarse fuera de Desarrollo: QA y Producción ni siquiera referencian la
// clase que la carga.

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using RedVital.Identidad.Dominio;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Infraestructura.Seguridad;

/// <summary>
/// Desarrollo y suite de pruebas. Lee la llave generada por la utilidad de
/// T-303.1. Nunca se registra en QA ni en Producción (ver Program.cs).
/// </summary>
public class ProveedorLlaveFirmaDesarrollo : IProveedorLlaveFirma
{
    private readonly RsaSecurityKey _clave;
    private const string Kid = "dev-key-1";

    public ProveedorLlaveFirmaDesarrollo(IConfiguration configuracion, IHostEnvironment entorno)
    {
        var relativa = configuracion["Jwt:LlavePrivadaDesarrollo"]
            ?? throw new InvalidOperationException(
                "Falta Jwt:LlavePrivadaDesarrollo. Configura la ruta local de la llave " +
                "privada mediante Jwt__LlavePrivadaDesarrollo; no guardes la llave en el repositorio.");
        var ruta = Path.GetFullPath(Path.Combine(entorno.ContentRootPath, relativa));

        var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(ruta));
        _clave = new RsaSecurityKey(rsa) { KeyId = Kid };
    }

    public (string Kid, SecurityKey ClavePrivada) ObtenerLlaveVigente() => (Kid, _clave);
}

/// <summary>
/// QA y Producción. La clave privada llega por archivo montado en
/// /run/secrets (nunca por variable de entorno ni por configuración
/// versionada — ver Documento de Infraestructura, sección de gestión de
/// secretos). El identificador de clave (kid) viene del nombre del archivo,
/// para que la rotación (cambiar el archivo montado) no requiera cambiar código.
/// </summary>
public class ProveedorLlaveFirmaProduccion : IProveedorLlaveFirma
{
    private readonly RsaSecurityKey _clave;
    private readonly string _kid;

    public ProveedorLlaveFirmaProduccion(IConfiguration configuracion)
    {
        var ruta = configuracion["Jwt:RutaSecretoFirma"] ?? "/run/secrets/identidad-clave-firma.pem";
        _kid = Path.GetFileNameWithoutExtension(ruta);

        var rsa = System.Security.Cryptography.RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(ruta));
        _clave = new RsaSecurityKey(rsa) { KeyId = _kid };
    }

    public (string Kid, SecurityKey ClavePrivada) ObtenerLlaveVigente() => (_kid, _clave);
}

/// <summary>
/// Utilidad de rotación: publica una clave pública nueva en la tabla
/// llave_firma (consumida por T-304.4) SIN retirar la anterior todavía —
/// la ventana de solapamiento (ADR-008: diez minutos antes de firmar con
/// ella, retiro de la anterior una hora después) se gestiona retirando la
/// clave vieja en una llamada posterior, no en esta.
/// </summary>
public class RotadorLlaveFirma
{
    private readonly IdentidadDbContext _contexto;

    public RotadorLlaveFirma(IdentidadDbContext contexto) => _contexto = contexto;

    public async Task PublicarNuevaAsync(string kid, string clavePublicaPem, CancellationToken ct = default)
    {
        _contexto.LlavesFirma.Add(new LlaveFirma
        {
            Kid = kid,
            ClavePublicaPem = clavePublicaPem,
            ActivaDesde = DateTimeOffset.UtcNow,
        });
        await _contexto.SaveChangesAsync(ct);
    }

    public async Task RetirarAsync(string kid, CancellationToken ct = default)
    {
        var llave = await _contexto.LlavesFirma.FindAsync(new object[] { kid }, ct);
        if (llave is not null)
        {
            llave.RetiradaEn = DateTimeOffset.UtcNow;
            await _contexto.SaveChangesAsync(ct);
        }
    }
}
