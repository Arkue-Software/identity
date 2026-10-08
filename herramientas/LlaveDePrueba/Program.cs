// RedVital — identity-service/herramientas/LlaveDePrueba
// T-303.1 — Par de llaves de prueba y tokens U3, U4 y de servicio.
//
// SOLO Desarrollo y suite de pruebas. La llave privada es material secreto:
// no se versiona ni se comparte. QA debe rechazar cualquier token firmado con
// ella (eso lo prueba T-303.3).
//
//   dotnet run -- generar-llave
//   dotnet run -- emitir-token --perfil operador
//   dotnet run -- emitir-token --perfil admin_banco
//   dotnet run -- emitir-token --perfil servicio --cliente donacion
//   dotnet run -- credencial-servicio --cliente gateway --secreto <secreto>
//     (imprime el INSERT para credencial_servicio en Desarrollo)
//   dotnet run -- semilla-identidad --clave <clave>
//     (imprime el conjunto sintético de cuentas institucionales U3–U7 para
//      Desarrollo y QA; el SRS V4 deja su alta desde la interfaz fuera de V1)

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

const string Kid = "dev-key-1"; // el mismo kid que publica identity-service en Development
var carpeta = Path.Combine(AppContext.BaseDirectory, "../../../llaves");
var privada = Path.GetFullPath(Path.Combine(carpeta, "dev-signing-key.private.pem"));
var publica = Path.GetFullPath(Path.Combine(carpeta, "dev-signing-key.public.pem"));

if (args.Length == 0) { Ayuda(); return 1; }

if (args[0] == "generar-llave")
{
    Directory.CreateDirectory(Path.GetDirectoryName(privada)!);
    using var rsa = RSA.Create(3072); // mismo tamaño que la llave real (Tech Radar, entrada 29)
    File.WriteAllText(privada, rsa.ExportPkcs8PrivateKeyPem());
    File.WriteAllText(publica, rsa.ExportSubjectPublicKeyInfoPem());
    Console.WriteLine($"Privada: {privada}\nPública: {publica}");
    Console.WriteLine("Solo Desarrollo/pruebas. Nunca la copies a QA.");
    return 0;
}

if (args[0] == "credencial-servicio")
{
    var cliente = Arg("--cliente");
    var secreto = Arg("--secreto");
    if (cliente is not ("gateway" or "donacion" or "notificaciones") || string.IsNullOrEmpty(secreto)) { Ayuda(); return 1; }
    // Mismo algoritmo con el que identity-service verifica (PasswordHasher de ASP.NET).
    var hash = new Microsoft.AspNetCore.Identity.PasswordHasher<object>().HashPassword(new object(), secreto);
    Console.WriteLine($"INSERT INTO credencial_servicio (cliente, secreto_hash) VALUES ('{cliente}', '{hash}');");
    Console.WriteLine($"-- El secreto en claro va SOLO en el archivo montado del cliente (p. ej. /run/secrets/{cliente}-secreto-cliente).");
    return 0;
}

if (args[0] == "semilla-identidad")
{
    var claveSemilla = Arg("--clave");
    if (string.IsNullOrEmpty(claveSemilla) || claveSemilla.Length < 10) { Console.Error.WriteLine("--clave: al menos 10 caracteres"); return 1; }
    var hasher = new Microsoft.AspNetCore.Identity.PasswordHasher<object>();
    // Identificadores fijos: las semillas de Campañas y Donación usan las mismas instituciones.
    const string BancoAurora = "a1000000-0000-4000-8000-000000000001";   // Medellín
    const string BancoCeiba = "a1000000-0000-4000-8000-000000000002";    // Bello
    const string AdminNacional = "b2000000-0000-4000-8000-000000000004";
    var cuentas = new (string Id, string Correo, string Nombre, string Rol, string Ambito, string? Codigo, string? Ruta, string? Institucion)[]
    {
        ("b2000000-0000-4000-8000-000000000001", "operador@redvital.test", "Andrés Mejía", "operador", "institucion", null, null, BancoAurora),
        ("b2000000-0000-4000-8000-000000000002", "admin.banco@redvital.test", "Catalina Duarte", "admin_banco", "institucion", null, null, BancoAurora),
        ("b2000000-0000-4000-8000-000000000003", "coordinador@redvital.test", "Jorge Salazar", "coordinador", "territorio", "05", "/00/05", null),
        (AdminNacional, "admin.nacional@redvital.test", "Marcela Torres", "admin_nacional", "territorio", "00", "/00", null),
        ("b2000000-0000-4000-8000-000000000005", "auditor@redvital.test", "Ricardo Peña", "auditor", "territorio", "00", "/00", null),
        ("b2000000-0000-4000-8000-000000000006", "operador.ceiba@redvital.test", "Lina Ospina", "operador", "institucion", null, null, BancoCeiba),
    };
    Console.WriteLine("-- RedVital · conjunto sintético de cuentas institucionales (Desarrollo y QA). Nunca en Producción.");
    Console.WriteLine("BEGIN;");
    foreach (var c in cuentas)
    {
        Console.WriteLine($"INSERT INTO usuario (id, correo, nombre, credencial_hash, rol_id) VALUES ('{c.Id}', '{c.Correo}', '{c.Nombre}', '{hasher.HashPassword(new object(), claveSemilla)}', '{c.Rol}') ON CONFLICT (correo) DO NOTHING;");
        var jurisdiccionId = "c3" + c.Id[2..];
        Console.WriteLine(c.Ambito == "institucion"
            ? $"INSERT INTO usuario_jurisdiccion (id, usuario_id, ambito, institucion_id, asignada_por) VALUES ('{jurisdiccionId}', '{c.Id}', 'institucion', '{c.Institucion}', '{AdminNacional}') ON CONFLICT (id) DO NOTHING;"
            : $"INSERT INTO usuario_jurisdiccion (id, usuario_id, ambito, territorio_codigo, territorio_ruta, asignada_por) VALUES ('{jurisdiccionId}', '{c.Id}', 'territorio', '{c.Codigo}', '{c.Ruta}', '{AdminNacional}') ON CONFLICT (id) DO NOTHING;");
    }
    Console.WriteLine("COMMIT;");
    return 0;
}

if (args[0] != "emitir-token") { Ayuda(); return 1; }
if (!File.Exists(privada)) { Console.Error.WriteLine("Primero: dotnet run -- generar-llave"); return 1; }

var perfil = Arg("--perfil");
var ahora = DateTimeOffset.UtcNow;
string sub, role, jurisdiction;

switch (perfil)
{
    case "operador":     // U3
        (sub, role, jurisdiction) = ("11111111-1111-1111-1111-111111111111", "operador", "institucion:22222222-2222-2222-2222-222222222222"); break;
    case "admin_banco":  // U4
        (sub, role, jurisdiction) = ("33333333-3333-3333-3333-333333333333", "admin_banco", "institucion:22222222-2222-2222-2222-222222222222"); break;
    case "servicio":
        var cliente = Arg("--cliente") ?? "donacion";
        if (cliente is not ("gateway" or "donacion" or "notificaciones")) { Console.Error.WriteLine("--cliente: gateway | donacion | notificaciones"); return 1; }
        (sub, role, jurisdiction) = (cliente, "servicio", ""); break;
    default:
        Ayuda(); return 1;
}

using var clave = RSA.Create();
clave.ImportFromPem(File.ReadAllText(privada));
var firma = new SigningCredentials(new RsaSecurityKey(clave) { KeyId = Kid }, SecurityAlgorithms.RsaSha256);

// Las ocho reivindicaciones de ADR-008, ni una más (sin datos personales).
var token = new JwtSecurityToken(claims: new[]
{
    new Claim("sub", sub),
    new Claim("role", role),
    new Claim("jurisdiction", jurisdiction),
    new Claim("iss", "https://identidad.redvital.local"),
    new Claim("aud", "redvital"),
    new Claim("iat", ahora.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
    new Claim("exp", ahora.AddMinutes(15).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
    new Claim("jti", Guid.NewGuid().ToString()),
}, signingCredentials: firma);

Console.WriteLine(new JwtSecurityTokenHandler().WriteToken(token));
return 0;

string? Arg(string nombre) { var i = Array.IndexOf(args, nombre); return i >= 0 && i + 1 < args.Length ? args[i + 1] : null; }
void Ayuda() => Console.WriteLine("dotnet run -- generar-llave | emitir-token --perfil operador|admin_banco|servicio [--cliente donacion] | credencial-servicio --cliente gateway --secreto <secreto> | semilla-identidad --clave <clave>");
