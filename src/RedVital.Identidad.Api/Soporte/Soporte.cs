// RedVital — identidad-service
// Correlación (lado servicio de T-305.5) y errores RFC 9457 del catálogo
// de increment-operations-sprint-3.md, sección 3.

using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace RedVital.Identidad.Api.Soporte;

public static class Correlacion
{
    public const string Cabecera = "X-Correlacion-Id";

    /// <summary>
    /// El gateway genera el identificador (T-305.5). Si la petición llega sin
    /// él (pruebas locales sin gateway), se genera aquí para que la auditoría
    /// nunca quede sin correlación. Siempre se devuelve en la respuesta.
    /// </summary>
    public static IApplicationBuilder UsarCorrelacion(this IApplicationBuilder app) =>
        app.Use(async (contexto, siguiente) =>
        {
            var valor = contexto.Request.Headers[Cabecera].ToString();
            if (string.IsNullOrWhiteSpace(valor) || valor.Length > 36)
                valor = Guid.NewGuid().ToString();
            contexto.Items[Cabecera] = valor;
            contexto.Response.OnStarting(() =>
            {
                contexto.Response.Headers[Cabecera] = valor;
                return Task.CompletedTask;
            });
            await siguiente();
        });

    public static string CorrelacionId(this HttpContext contexto) =>
        contexto.Items[Cabecera] as string ?? Guid.NewGuid().ToString();
}

public static class Problemas
{
    public static IActionResult SesionInvalida(string correlacionId, string detalle) =>
        Crear(401, "sesion-invalida", "Sesión inválida", detalle, correlacionId);

    public static IActionResult OperacionNoPermitida(string correlacionId) =>
        Crear(403, "operacion-no-permitida", "Operación no permitida", "El rol no autoriza esta operación.", correlacionId);

    public static IActionResult Crear(int estado, string tipo, string titulo, string detalle, string correlacionId) =>
        new ObjectResult(new { tipo, titulo, estado, detalle, correlacion_id = correlacionId })
        {
            StatusCode = estado,
            ContentTypes = { "application/problem+json" },
        };

    /// <summary>Escritura directa, para los rechazos de la autenticación (401/403).</summary>
    public static Task EscribirAsync(HttpContext contexto, int estado, string tipo, string titulo, string detalle)
    {
        contexto.Response.StatusCode = estado;
        contexto.Response.ContentType = "application/problem+json";
        return contexto.Response.WriteAsync(JsonSerializer.Serialize(new
        {
            tipo, titulo, estado, detalle, correlacion_id = contexto.CorrelacionId(),
        }));
    }
}
