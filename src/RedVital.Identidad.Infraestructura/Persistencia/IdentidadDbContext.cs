// RedVital — identidad-service
// Mapea contra el esquema de redvital-databases/identidad/schema.sql.
// No se usa Database.Migrate() ni Database.EnsureCreated() en ningún lugar
// del código de este servicio: el esquema lo aplica ese otro repositorio.

using Microsoft.EntityFrameworkCore;
using RedVital.Identidad.Dominio;

namespace RedVital.Identidad.Infraestructura.Persistencia;

public class IdentidadDbContext : DbContext
{
    public IdentidadDbContext(DbContextOptions<IdentidadDbContext> options) : base(options) { }

    public DbSet<Usuario> Usuarios => Set<Usuario>();
    public DbSet<Rol> Roles => Set<Rol>();
    public DbSet<UsuarioJurisdiccion> UsuarioJurisdicciones => Set<UsuarioJurisdiccion>();
    public DbSet<Sesion> Sesiones => Set<Sesion>();
    public DbSet<CredencialServicio> CredencialesServicio => Set<CredencialServicio>();
    public DbSet<RegistroAuditoriaIdent> RegistroAuditoriaIdent => Set<RegistroAuditoriaIdent>();
    public DbSet<LlaveFirma> LlavesFirma => Set<LlaveFirma>();
    public DbSet<OperacionIdempotente> OperacionesIdempotentes => Set<OperacionIdempotente>();

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Usuario>(e =>
        {
            e.ToTable("usuario");
            e.HasKey(u => u.Id);
            e.Property(u => u.Id).HasColumnName("id");
            e.Property(u => u.Correo).HasColumnName("correo");
            e.Property(u => u.Nombre).HasColumnName("nombre");
            e.Property(u => u.CredencialHash).HasColumnName("credencial_hash");
            e.Property(u => u.RolCodigo).HasColumnName("rol_id");
            e.HasOne(u => u.Rol).WithMany().HasForeignKey(u => u.RolCodigo);
            e.Property(u => u.Activo).HasColumnName("activo");
            e.Property(u => u.UltimoAccesoEn).HasColumnName("ultimo_acceso_en");
            e.Property(u => u.CreadoEn).HasColumnName("creado_en");
            e.Property(u => u.ActualizadoEn).HasColumnName("actualizado_en");
        });

        modelBuilder.Entity<Rol>(e =>
        {
            e.ToTable("rol");
            e.HasKey(r => r.Codigo);
            e.Property(r => r.Codigo).HasColumnName("codigo");
            e.Property(r => r.Perfil).HasColumnName("perfil");
            e.Property(r => r.AmbitoAdmitido).HasColumnName("ambito_admitido");
        });

        modelBuilder.Entity<UsuarioJurisdiccion>(e =>
        {
            e.ToTable("usuario_jurisdiccion");
            e.HasKey(j => j.Id);
            e.Property(j => j.Id).HasColumnName("id");
            e.Property(j => j.UsuarioId).HasColumnName("usuario_id");
            e.HasOne(j => j.Usuario).WithMany(u => u.Jurisdicciones).HasForeignKey(j => j.UsuarioId);
            e.Property(j => j.Ambito).HasColumnName("ambito");
            e.Property(j => j.TerritorioCodigo).HasColumnName("territorio_codigo");
            e.Property(j => j.TerritorioRuta).HasColumnName("territorio_ruta");
            e.Property(j => j.InstitucionId).HasColumnName("institucion_id");
            e.Property(j => j.AsignadaPor).HasColumnName("asignada_por");
            e.Property(j => j.VigenteDesde).HasColumnName("vigente_desde");
            e.Property(j => j.VigenteHasta).HasColumnName("vigente_hasta");
        });

        modelBuilder.Entity<Sesion>(e =>
        {
            e.ToTable("sesion");
            e.HasKey(s => s.Id);
            e.Property(s => s.Id).HasColumnName("id");
            e.Property(s => s.UsuarioId).HasColumnName("usuario_id");
            e.HasOne(s => s.Usuario).WithMany(u => u.Sesiones).HasForeignKey(s => s.UsuarioId);
            e.Property(s => s.SecretoHash).HasColumnName("secreto_hash");
            e.Property(s => s.EmitidaEn).HasColumnName("emitida_en");
            e.Property(s => s.ExpiraEn).HasColumnName("expira_en");
            e.Property(s => s.RenovadaEn).HasColumnName("renovada_en");
            e.Property(s => s.RevocadaEn).HasColumnName("revocada_en");
            e.Property(s => s.MotivoRevocacion).HasColumnName("motivo_revocacion");
            e.Property(s => s.Origen).HasColumnName("origen");
        });

        modelBuilder.Entity<CredencialServicio>(e =>
        {
            e.ToTable("credencial_servicio");
            e.HasKey(c => c.Id);
            e.Property(c => c.Id).HasColumnName("id");
            e.Property(c => c.Cliente).HasColumnName("cliente");
            e.Property(c => c.SecretoHash).HasColumnName("secreto_hash");
            e.Property(c => c.Activa).HasColumnName("activa");
            e.Property(c => c.CreadaEn).HasColumnName("creada_en");
            e.Property(c => c.RotadaEn).HasColumnName("rotada_en");
        });

        modelBuilder.Entity<RegistroAuditoriaIdent>(e =>
        {
            e.ToTable("registro_auditoria_ident");
            e.HasKey(r => r.Id);
            e.Property(r => r.Id).HasColumnName("id");
            e.Property(r => r.ActorTipo).HasColumnName("actor_tipo");
            e.Property(r => r.ActorId).HasColumnName("actor_id");
            e.Property(r => r.Rol).HasColumnName("rol");
            e.Property(r => r.JurisdiccionSolicitada).HasColumnName("jurisdiccion_solicitada");
            e.Property(r => r.Operacion).HasColumnName("operacion");
            e.Property(r => r.RecursoTipo).HasColumnName("recurso_tipo");
            e.Property(r => r.RecursoId).HasColumnName("recurso_id");
            e.Property(r => r.Resultado).HasColumnName("resultado");
            e.Property(r => r.CorrelacionId).HasColumnName("correlacion_id");
            e.Property(r => r.Origen).HasColumnName("origen");
            e.Property(r => r.OcurridoEn).HasColumnName("ocurrido_en");
        });

        modelBuilder.Entity<LlaveFirma>(e =>
        {
            e.ToTable("llave_firma");
            e.HasKey(k => k.Kid);
            e.Property(k => k.Kid).HasColumnName("kid");
            e.Property(k => k.ClavePublicaPem).HasColumnName("clave_publica_pem");
            e.Property(k => k.ActivaDesde).HasColumnName("activa_desde");
            e.Property(k => k.RetiradaEn).HasColumnName("retirada_en");
        });

        modelBuilder.Entity<OperacionIdempotente>(e =>
        {
            e.ToTable("operacion_idempotente");
            e.HasKey(o => new { o.Sujeto, o.Clave });
            e.Property(o => o.Sujeto).HasColumnName("sujeto");
            e.Property(o => o.Clave).HasColumnName("clave");
            e.Property(o => o.Operacion).HasColumnName("operacion");
            e.Property(o => o.HuellaPeticion).HasColumnName("huella_peticion");
            e.Property(o => o.RecursoId).HasColumnName("recurso_id");
            e.Property(o => o.CreadoEn).HasColumnName("creado_en");
            e.Property(o => o.ExpiraEn).HasColumnName("expira_en");
        });
    }
}
