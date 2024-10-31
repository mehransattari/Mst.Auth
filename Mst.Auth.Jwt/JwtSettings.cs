namespace Mst.Auth.Jwt;

public class JwtSettings
{
    public required string SecretKey { get; set; }
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public int ExpiryMinutes { get; set; }
    public int RefreshTokenExpiryDays { get; set; }
}
