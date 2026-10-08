// RedVital — identidad-service
// Conecta T-304.2, T-304.3, T-304.4, T-330.1, T-330.2, T-330.3 y T-330.4.
// T-303.2: en Development usa la llave de prueba; en cualquier otro ambiente
// (QA, Production) esa clase ni siquiera se registra.

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RedVital.Identidad.Api.Soporte;
using RedVital.Identidad.Aplicacion.CasosDeUso;
using RedVital.Identidad.Dominio;
using RedVital.Identidad.Infraestructura.Auditoria;
using RedVital.Identidad.Infraestructura.Persistencia;
using RedVital.Identidad.Infraestructura.Seguridad;

// Comprobación de salud del contenedor: la imagen no trae curl, así que el
// propio ejecutable consulta /salud y termina con 0 o 1.
if (args.Contains("--salud")) return await Salud.ComprobarAsync();

var builder = WebApplication.CreateBuilder(args);

// Secretos como archivos montados en /run/secrets: la contraseña de la base
// (identidad_servicio) nunca va en la cadena de conexión versionada.
builder.Configuration.AddKeyPerFile(builder.Configuration["Secretos:Directorio"] ?? "/run/secrets", optional: true);
var cadena = CadenaConexion.ConClave(builder.Configuration.GetConnectionString("Identidad"),
                 builder.Configuration["identidad_servicio"])
    ?? throw new InvalidOperationException("Falta ConnectionStrings:Identidad.");
builder.Services.AddDbContext<IdentidadDbContext>(o => o.UseNpgsql(cadena));

// Casos de uso
builder.Services.AddScoped<EmisorTokenAcceso>();
builder.Services.AddScoped<IniciarSesion>();          // T-304.2 + T-304.3
builder.Services.AddScoped<ObtenerClavesPublicas>();  // T-304.4
builder.Services.AddScoped<RenovarSesion>();          // T-330.1
builder.Services.AddScoped<CerrarSesion>();           // T-330.2
builder.Services.AddScoped<EmitirTokenServicio>();    // T-330.3
builder.Services.AddScoped<IRegistradorAuditoria, RegistradorAuditoria>(); // T-330.4
builder.Services.AddScoped<CrearCuentaDonante>();     // RF-01, alta desde Donación
builder.Services.AddScoped<ConsultarUsuarioActual>(); // GET /v1/usuarios/me
builder.Services.AddHealthChecks();

// T-303.2 / T-303.3: la llave de prueba solo existe para Development.
if (builder.Environment.IsDevelopment())
    builder.Services.AddSingleton<IProveedorLlaveFirma, ProveedorLlaveFirmaDesarrollo>();
else
    builder.Services.AddSingleton<IProveedorLlaveFirma, ProveedorLlaveFirmaProduccion>();

// Validación de tokens dentro de Identidad (EC-03)
builder.Services.AddSingleton<ClavesValidacionIdentidad>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
    .Configure<ClavesValidacionIdentidad, IConfiguration>((o, claves, conf) =>
    {
        o.MapInboundClaims = false; // conserva "sub", "role", "jurisdiction" tal cual
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = conf["Jwt:Emisor"],
            ValidAudience = conf["Jwt:Audiencia"],
            ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 },
            IssuerSigningKeyResolver = (_, _, _, _) => claves.Obtener(),
            NameClaimType = "sub",
            RoleClaimType = "role",
            ClockSkew = TimeSpan.FromSeconds(30),
        };
        o.Events = new JwtBearerEvents
        {
            OnChallenge = async c =>
            {
                c.HandleResponse();
                await Problemas.EscribirAsync(c.HttpContext, 401, "sesion-invalida", "Sesión inválida", "El token es inválido o expiró.");
            },
            OnForbidden = c => Problemas.EscribirAsync(c.HttpContext, 403, "operacion-no-permitida", "Operación no permitida", "El rol no autoriza esta operación."),
        };
    });

builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("SoloGateway", p => p.RequireClaim("role", "servicio").RequireClaim("sub", "gateway"));
    o.AddPolicy("SoloDonacion", p => p.RequireClaim("role", "servicio").RequireClaim("sub", "donacion"));
});

// Contrato en snake_case: token_acceso, expira_en, correlacion_id…
// La misma política aplica a la lectura de los cuerpos que llegan.
builder.Services.AddControllers().AddJsonOptions(o =>
    o.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower);

var app = builder.Build();

// Publica en llave_firma la parte pública de la llave vigente, para que el
// JWKS (T-304.4) la exponga y APISIX y los servicios validen los tokens.
// En Development es la llave de prueba; en QA y Producción, la llave montada
// en /run/secrets. Como cada ambiente solo registra su propio proveedor, el
// JWKS de QA jamás contiene la llave de prueba (T-303.3).
{
    using var scope = app.Services.CreateScope();
    var contexto = scope.ServiceProvider.GetRequiredService<IdentidadDbContext>();
    var (kid, clave) = scope.ServiceProvider.GetRequiredService<IProveedorLlaveFirma>().ObtenerLlaveVigente();
    if (!contexto.LlavesFirma.Any(k => k.Kid == kid) && clave is RsaSecurityKey rsaKey && rsaKey.Rsa is not null)
    {
        contexto.LlavesFirma.Add(new LlaveFirma
        {
            Kid = kid,
            ClavePublicaPem = rsaKey.Rsa.ExportSubjectPublicKeyInfoPem(),
            ActivaDesde = DateTimeOffset.UtcNow,
        });
        contexto.SaveChanges();
    }
}

app.UsarCorrelacion();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.MapHealthChecks("/salud");
await app.RunAsync();
return 0;

public partial class Program { } // permite pruebas de integración con WebApplicationFactory
