namespace Mst.Auth.Jwt;

public class RolePermissionConfig
{
    public List<ProtectedEndpoint> ProtectedEndpoints { get; set; } = new();
    public List<string> ExcludedPaths { get; set; } = new();
}
