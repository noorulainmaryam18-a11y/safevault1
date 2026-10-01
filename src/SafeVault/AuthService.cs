using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace SafeVault;

public class AuthService
{
    public const string Issuer = "SafeVault", Audience = "SafeVaultUsers";
    private readonly UserRepository _repo;
    private readonly SymmetricSecurityKey _key;

    public AuthService(UserRepository repo, string jwtKey)
    {
        _repo = repo;
        _key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));
    }
    public static SymmetricSecurityKey MakeKey(string k) => new(Encoding.UTF8.GetBytes(k));

    public static string Hash(string password) => BCrypt.Net.BCrypt.HashPassword(password, 12);

    /// <summary>Returns a JWT or null. Same result for unknown user / wrong password (no user enumeration).</summary>
    public string? Login(string username, string password)
    {
        var u = _repo.GetByUsername(username);
        if (u is null) { BCrypt.Net.BCrypt.Verify(password, Hash("dummy-password")); return null; }
        if (!BCrypt.Net.BCrypt.Verify(password, u.PasswordHash)) return null;

        var claims = new[] {
            new Claim(ClaimTypes.Name, u.Username),
            new Claim(ClaimTypes.Role, u.Role) };
        var token = new JwtSecurityToken(Issuer, Audience, claims,
            expires: DateTime.UtcNow.AddMinutes(30),
            signingCredentials: new SigningCredentials(_key, SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
