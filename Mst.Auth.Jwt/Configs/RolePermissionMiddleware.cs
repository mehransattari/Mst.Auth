using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace Mst.Auth.Jwt;

public class RolePermissionMiddleware
{
    private readonly RequestDelegate _next;
    private readonly RolePermissionConfig _config;

    public RolePermissionMiddleware(RequestDelegate next, IOptions<RolePermissionConfig> config)
    {
        _next = next;
        _config = config.Value;
    }

    public async Task Invoke(HttpContext context)
    {
        var path = context.Request.Path.Value?.ToLower();

        if(path is null)
        {
            await _next(context);
            return;
        }

        // ExcludedPaths
        if (_config.ExcludedPaths.Any(excluded => path.Equals(excluded.ToLower())))
        {
            await _next(context);
            return;
        }

        // ProtectedEndpoints
        var protectedEndpoint = _config.ProtectedEndpoints.FirstOrDefault(endpoint => path.Equals(endpoint.Path.ToLower()));

        if (protectedEndpoint != null)
        {
            var userRoles = context.User.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                .ToList();

            var userPermissions = context.User.Claims
                .Where(c => c.Type == "Permission")
                .Select(c => c.Value)
                .ToList();

            if(userRoles.Any())
            {
                // Exist appSetting Role in database
                var isExistRoles = !protectedEndpoint.Roles.Any() ||
                                 protectedEndpoint.Roles.Any(role => userRoles.Contains(role));

                if (!isExistRoles)
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsync("Access Denied");
                    return;
                }
            }

            if (userPermissions.Any())
            {
                // Exist appSetting Permissions in database
                var isExistPersmissions = !protectedEndpoint.Permissions.Any() ||
                                      protectedEndpoint.Permissions.Any(permission => userPermissions.Contains(permission));

                if (!isExistPersmissions)
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsync("Access Denied");
                    return;
                }
            }
          
        }

        await _next(context);
    }
}
