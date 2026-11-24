// RedVital — identidad-service
// Usado por T-304.3 (emisión inicial) y T-330.1 (renovación) — ambas
// necesitan la misma regla: "la jurisdicción vigente AL MOMENTO de emitir".

using RedVital.Identidad.Dominio;

namespace RedVital.Identidad.Aplicacion.CasosDeUso;

public static class ResolverJurisdiccion
{
    /// <summary>
    /// RF-22 exige que un cambio de jurisdicción surta efecto "a partir del
    /// siguiente token de acceso emitido" — nunca en los ya emitidos. Por eso
    /// esto se evalúa en cada emisión y nunca se cachea más allá de un token.
    /// </summary>
    public static string Vigente(Usuario usuario, DateTimeOffset ahora)
    {
        var vigente = usuario.Jurisdicciones
            .Where(j => j.VigenteDesde <= ahora && (j.VigenteHasta is null || j.VigenteHasta > ahora))
            .OrderByDescending(j => j.VigenteDesde)
            .FirstOrDefault();

        // El rol "donante" no tiene jurisdicción — RF-23: U1 (anónimo) ni
        // siquiera inicia sesión; U2 (registrado) sí, sin jurisdicción.
        return vigente?.ComoReivindicacion() ?? "";
    }
}
