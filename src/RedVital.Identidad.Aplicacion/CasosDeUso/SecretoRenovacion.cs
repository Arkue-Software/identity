// RedVital — identidad-service
// Secreto de la cookie de renovación: 32 bytes del generador criptográfico del
// sistema, en hexadecimal. Lo usan el inicio de sesión (T-304.2) y cada
// renovación (T-330.1).

using System.Security.Cryptography;

namespace RedVital.Identidad.Aplicacion.CasosDeUso;

public static class SecretoRenovacion
{
    public static string Generar() => Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
}
