// RedVital — identidad-service
// Entidades de dominio. El esquema real vive en redvital-databases/identidad —
// estas clases se mapean contra él, no lo generan.

namespace RedVital.Identidad.Dominio;

public class Usuario
{
    public Guid Id { get; set; }
    public required string Correo { get; set; }
    public string? Nombre { get; set; }
    public required string CredencialHash { get; set; }
    public required string RolCodigo { get; set; }
    public Rol? Rol { get; set; }
    public bool Activo { get; set; } = true;
    public DateTimeOffset? UltimoAccesoEn { get; set; }
    public DateTimeOffset CreadoEn { get; set; }
    public DateTimeOffset ActualizadoEn { get; set; }
    public ICollection<UsuarioJurisdiccion> Jurisdicciones { get; set; } = new List<UsuarioJurisdiccion>();
    public ICollection<Sesion> Sesiones { get; set; } = new List<Sesion>();
}

public class Rol
{
    public required string Codigo { get; set; }
    public required string Perfil { get; set; }
    public required string AmbitoAdmitido { get; set; }
}

public class UsuarioJurisdiccion
{
    public Guid Id { get; set; }
    public Guid UsuarioId { get; set; }
    public Usuario? Usuario { get; set; }
    public required string Ambito { get; set; }
    public string? TerritorioCodigo { get; set; }
    public string? TerritorioRuta { get; set; }
    public Guid? InstitucionId { get; set; }
    public Guid AsignadaPor { get; set; }
    public DateTimeOffset VigenteDesde { get; set; }
    public DateTimeOffset? VigenteHasta { get; set; }

    /// <summary>
    /// Forma exacta en la que esta jurisdicción viaja dentro de la
    /// reivindicación "jurisdiction" del token (ADR-008).
    /// </summary>
    public string ComoReivindicacion() => Ambito switch
    {
        "territorio" => $"territorio:{TerritorioRuta}",
        "institucion" => $"institucion:{InstitucionId}",
        _ => throw new InvalidOperationException($"Ámbito no reconocido: {Ambito}")
    };
}

public class Sesion
{
    public Guid Id { get; set; }
    public Guid UsuarioId { get; set; }
    public Usuario? Usuario { get; set; }
    public required string SecretoHash { get; set; }
    public DateTimeOffset EmitidaEn { get; set; }
    public DateTimeOffset ExpiraEn { get; set; }
    public DateTimeOffset? RenovadaEn { get; set; }
    public DateTimeOffset? RevocadaEn { get; set; }
    public string? MotivoRevocacion { get; set; }
    public string? Origen { get; set; }

    public bool EstaVigente(DateTimeOffset ahora) =>
        RevocadaEn is null && ExpiraEn > ahora;
}

public class CredencialServicio
{
    public Guid Id { get; set; }
    public required string Cliente { get; set; }
    public required string SecretoHash { get; set; }
    public bool Activa { get; set; } = true;
    public DateTimeOffset CreadaEn { get; set; }
    public DateTimeOffset? RotadaEn { get; set; }
}

public class RegistroAuditoriaIdent
{
    public Guid Id { get; set; }
    public required string ActorTipo { get; set; }
    public string? ActorId { get; set; }
    public string? Rol { get; set; }
    public string? JurisdiccionSolicitada { get; set; }
    public required string Operacion { get; set; }
    public required string RecursoTipo { get; set; }
    public Guid? RecursoId { get; set; }
    public required string Resultado { get; set; }
    public required string CorrelacionId { get; set; }
    public string? Origen { get; set; }
    public DateTimeOffset OcurridoEn { get; set; }
}

/// <summary>Metadatos de una llave de firma publicada en el JWKS (T-304.4).</summary>
public class LlaveFirma
{
    public required string Kid { get; set; }
    public required string ClavePublicaPem { get; set; }
    public DateTimeOffset ActivaDesde { get; set; }
    public DateTimeOffset? RetiradaEn { get; set; }
    public bool EstaPublicada(DateTimeOffset ahora) => RetiradaEn is null || RetiradaEn > ahora;
}

/// <summary>Reconocimiento de reenvíos del alta de cuentas (EC-10).</summary>
public class OperacionIdempotente
{
    public required string Sujeto { get; set; }
    public required string Clave { get; set; }
    public required string Operacion { get; set; }
    public required string HuellaPeticion { get; set; }
    public Guid RecursoId { get; set; }
    public DateTimeOffset CreadoEn { get; set; }
    public DateTimeOffset ExpiraEn { get; set; }
}
