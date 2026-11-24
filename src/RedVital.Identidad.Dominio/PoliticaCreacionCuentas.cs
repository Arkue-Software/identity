namespace RedVital.Identidad.Dominio;

public enum RolCuenta { U1 = 1, U2, U3, U4, U5, U6, U7 }

public sealed record Solicitante(Guid CuentaId, RolCuenta Rol, string? RutaTerritorial, Guid? BancoId);

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

    /// <summary>Convierte entradas como "05", "05.05001" o "05001" al formato DIVIPOLA "/00/05/05001".</summary>
    public static string? NormalizarRuta(string? ruta)
    {
        if (string.IsNullOrWhiteSpace(ruta)) return null;
        var limpia = ruta.Trim().TrimEnd('/');
        if (limpia.StartsWith("/00", StringComparison.Ordinal)) return limpia;

        var partes = limpia.TrimStart('/').Replace('.', '/').Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (partes.Length == 1 && partes[0].Length == 5)
            return $"/00/{partes[0][..2]}/{partes[0]}";
        return "/00/" + string.Join('/', partes);
    }

    public static bool EnJurisdiccion(Solicitante s, NuevaCuenta n) => s.Rol switch
    {
        RolCuenta.U6 => true,
        RolCuenta.U5 => NormalizarRuta(s.RutaTerritorial) is { } sr
                        && NormalizarRuta(n.RutaTerritorial) is { } nr
                        && (nr == sr || nr.StartsWith(sr + "/", StringComparison.Ordinal)),
        RolCuenta.U4 => s.BancoId is not null && n.BancoId == s.BancoId,
        _ => false,
    };
}
