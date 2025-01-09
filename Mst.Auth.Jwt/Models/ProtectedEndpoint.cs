namespace Mst.Auth.Jwt;

public class ProtectedEndpoint
{
    public string? Path { get; set; }
    public List<string> Roles { get; set; } = new();
    public List<string> Permissions { get; set; } = new();
}
