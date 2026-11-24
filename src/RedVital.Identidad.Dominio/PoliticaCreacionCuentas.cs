// Identity service (.NET) — capa Dominio. Sin dependencias externas.
// Regla: cada rol solo crea roles de nivel inferior. U7 (auditor) y U1/U2/U3 no crean cuentas.
namespace RedVital.Identidad.Dominio;

public enum RolCuenta { U1 = 1, U2, U3, U4, U5, U6, U7 }

/// Quien hace la petición, tomado del JWT (nunca del cuerpo de la petición).
public sealed record Solicitante(Guid CuentaId, RolCuenta Rol, string? RutaTerritorial, Guid? BancoId);

/// Datos de la cuenta que se quiere crear.
public sealed record NuevaCuenta(string Correo, string Nombre, RolCuenta Rol, string? RutaTerritorial, Guid? BancoId);

public static class PoliticaCreacionCuentas
{
    private static readonly IReadOnlyDictionary<RolCuenta, RolCuenta[]> Creables =
        new Dictionary<RolCuenta, RolCuenta[]>
        {
            [RolCuenta.U6] = new[] { RolCuenta.U5, RolCuenta.U4, RolCuenta.U3 },
            [RolCuenta.U5] = new[] { RolCuenta.U4, RolCuenta.U3 },
            [RolCuenta.U4] = new[] { RolCuenta.U3 },
        };

    public static IReadOnlyCollection<RolCuenta> RolesCreables(RolCuenta solicitante) =>
        Creables.TryGetValue(solicitante, out var roles) ? roles : Array.Empty<RolCuenta>();

    public static bool PuedeCrearRol(RolCuenta solicitante, RolCuenta objetivo) =>
        RolesCreables(solicitante).Contains(objetivo);

    /// La cuenta nueva debe quedar dentro de la jurisdicción de quien la crea.
    public static bool EnJurisdiccion(Solicitante s, NuevaCuenta n) => s.Rol switch
    {
        RolCuenta.U6 => true, // país entero
        RolCuenta.U5 => s.RutaTerritorial is not null
                        && n.RutaTerritorial is not null
                        && (n.RutaTerritorial == s.RutaTerritorial
                            || n.RutaTerritorial.StartsWith(s.RutaTerritorial + ".", StringComparison.Ordinal)),
        RolCuenta.U4 => s.BancoId is not null && n.BancoId == s.BancoId,
        _ => false,
    };
}
