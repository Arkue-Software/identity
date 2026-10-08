// RedVital — identidad-service. Utilidades de arranque en contenedor.

namespace RedVital.Identidad.Api.Soporte;

public static class CadenaConexion
{
    /// <summary>Agrega la contraseña, leída de un secreto en archivo, si la cadena no la trae.</summary>
    public static string? ConClave(string? cadena, string? clave) =>
        cadena is null || string.IsNullOrWhiteSpace(clave) || cadena.Contains("Password=", StringComparison.OrdinalIgnoreCase)
            ? cadena
            : $"{cadena.TrimEnd(';')};Password={clave.Trim()}";
}

public static class Salud
{
    public static async Task<int> ComprobarAsync()
    {
        try
        {
            using var cliente = new HttpClient { Timeout = TimeSpan.FromSeconds(4) };
            var puerto = Environment.GetEnvironmentVariable("ASPNETCORE_HTTP_PORTS")?.Split(';')[0] ?? "8080";
            var respuesta = await cliente.GetAsync($"http://127.0.0.1:{puerto}/salud");
            return respuesta.IsSuccessStatusCode ? 0 : 1;
        }
        catch
        {
            return 1;
        }
    }
}
