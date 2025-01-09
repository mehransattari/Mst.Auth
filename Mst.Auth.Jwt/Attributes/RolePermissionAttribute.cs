namespace Mst.Auth.Jwt;

[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class, AllowMultiple = true)]
public class RolePermissionAttribute : Attribute
{
    public string[] Roles { get; }
    public string[] Permissions { get; }

    public RolePermissionAttribute(string[] roles = null, string[] permissions = null)
    {
        Roles = roles ?? Array.Empty<string>();
        Permissions = permissions ?? Array.Empty<string>();
    }
}
