// RedVital — identidad-service
// Extraído de T-304.3 para que T-330.1 (renovación) y T-330.3 (token de
// servicio) no dupliquen la lógica de las ocho reivindicaciones de ADR-008.

using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using RedVital.Identidad.Dominio;

namespace RedVital.Identidad.Aplicacion.CasosDeUso;

public class EmisorTokenAcceso
{
    private readonly IProveedorLlaveFirma _proveedorLlave;

    public EmisorTokenAcceso(IProveedorLlaveFirma proveedorLlave) => _proveedorLlave = proveedorLlave;

    /// <summary>Token de acceso para un usuario (T-304.3, reutilizado por T-330.1).</summary>
    public string EmitirParaUsuario(Usuario usuario, string jurisdiccion, DateTimeOffset ahora)
    {
        var claims = new List<Claim>
        {
            new("sub", usuario.Id.ToString()),
            new("role", usuario.RolCodigo),
            new("jurisdiction", jurisdiccion),
        };
        return FirmarToken(claims, ahora, vigenciaMinutos: 15);
    }

    /// <summary>
    /// Token de servicio para un proceso sin usuario (T-330.3). "sub" es el
    /// nombre del cliente, "role" es "servicio", sin jurisdicción.
    /// </summary>
    public string EmitirParaServicio(string cliente, DateTimeOffset ahora)
    {
        var claims = new List<Claim>
        {
            new("sub", cliente),
            new("role", "servicio"),
            new("jurisdiction", ""),
        };
        // Vigencia de quince minutos también para el token de servicio —
        // el DD lo fija igual que el de usuario (sección de seguridad operativa).
        return FirmarToken(claims, ahora, vigenciaMinutos: 15);
    }

    private string FirmarToken(List<Claim> claimsEspecificos, DateTimeOffset ahora, int vigenciaMinutos)
    {
        var (kid, clavePrivada) = _proveedorLlave.ObtenerLlaveVigente();

        var claims = new List<Claim>(claimsEspecificos)
        {
            new("iss", "https://identidad.redvital.local"),
            new("aud", "redvital"),
            new("iat", ahora.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("exp", ahora.AddMinutes(vigenciaMinutos).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new("jti", Guid.NewGuid().ToString()),
        };

        var credencialFirma = new SigningCredentials(clavePrivada, SecurityAlgorithms.RsaSha256)
        {
            Key = { KeyId = kid }
        };

        var token = new JwtSecurityToken(claims: claims, signingCredentials: credencialFirma);
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
