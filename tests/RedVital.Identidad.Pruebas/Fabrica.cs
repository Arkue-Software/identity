// Utilidades comunes a las pruebas de identity-service.

using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RedVital.Identidad.Aplicacion.CasosDeUso;
using RedVital.Identidad.Dominio;
using RedVital.Identidad.Infraestructura.Auditoria;
using RedVital.Identidad.Infraestructura.Persistencia;

namespace RedVital.Identidad.Pruebas;

/// <summary>Llave de firma generada en memoria para cada prueba.</summary>
public class ProveedorDePrueba : IProveedorLlaveFirma
{
    public RSA Rsa { get; } = RSA.Create(2048);
    public string Kid { get; init; } = "prueba-1";
    public (string Kid, SecurityKey ClavePrivada) ObtenerLlaveVigente() => (Kid, new RsaSecurityKey(Rsa) { KeyId = Kid });
}

public class Entorno
{
    public const string Emisor = "https://identidad.redvital.local";
    public const string Audiencia = "redvital";
    public static readonly Guid Institucion = Guid.Parse("22222222-2222-2222-2222-222222222222");

    public IdentidadDbContext Contexto { get; }
    public ProveedorDePrueba Llave { get; } = new();
    public EmisorTokenAcceso Emisor_ { get; }
    public RegistradorAuditoria Auditoria { get; }

    public Entorno()
    {
        Contexto = new IdentidadDbContext(new DbContextOptionsBuilder<IdentidadDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        Contexto.Roles.AddRange(
            new Rol { Codigo = "donante", Perfil = "U2", AmbitoAdmitido = "ninguno" },
            new Rol { Codigo = "operador", Perfil = "U3", AmbitoAdmitido = "institucion" },
            new Rol { Codigo = "admin_banco", Perfil = "U4", AmbitoAdmitido = "institucion" });
        Contexto.LlavesFirma.Add(new LlaveFirma
        {
            Kid = Llave.Kid,
            ClavePublicaPem = Llave.Rsa.ExportSubjectPublicKeyInfoPem(),
            ActivaDesde = DateTimeOffset.UtcNow.AddMinutes(-20),
        });
        Contexto.SaveChanges();

        Emisor_ = new EmisorTokenAcceso(Llave);
        Auditoria = new RegistradorAuditoria(Contexto);
    }

    public IniciarSesion IniciarSesion() => new(Contexto, Emisor_, Auditoria);
    public RenovarSesion RenovarSesion() => new(Contexto, Emisor_, Auditoria);
    public CerrarSesion CerrarSesion() => new(Contexto, Auditoria);
    public EmitirTokenServicio EmitirTokenServicio() => new(Contexto, Emisor_, Auditoria);
    public ObtenerClavesPublicas ObtenerClavesPublicas() => new(Contexto);

    public Usuario CrearOperador(string correo = "operador@banco-ficticio.test", string clave = "Clave-Prueba-123")
    {
        var usuario = new Usuario
        {
            Id = Guid.NewGuid(), Correo = correo, CredencialHash = "", RolCodigo = "operador",
            CreadoEn = DateTimeOffset.UtcNow, ActualizadoEn = DateTimeOffset.UtcNow,
        };
        usuario.CredencialHash = new PasswordHasher<Usuario>().HashPassword(usuario, clave);
        usuario.Jurisdicciones.Add(new UsuarioJurisdiccion
        {
            Id = Guid.NewGuid(), UsuarioId = usuario.Id, Ambito = "institucion",
            InstitucionId = Institucion, AsignadaPor = Guid.NewGuid(),
            VigenteDesde = DateTimeOffset.UtcNow.AddDays(-1),
        });
        Contexto.Usuarios.Add(usuario);
        Contexto.SaveChanges();
        return usuario;
    }

    public void CrearCredencialServicio(string cliente, string secreto)
    {
        var credencial = new CredencialServicio { Id = Guid.NewGuid(), Cliente = cliente, SecretoHash = "", CreadaEn = DateTimeOffset.UtcNow };
        credencial.SecretoHash = new PasswordHasher<CredencialServicio>().HashPassword(credencial, secreto);
        Contexto.CredencialesServicio.Add(credencial);
        Contexto.SaveChanges();
    }
}
