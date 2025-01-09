using Microsoft.AspNetCore.Http;
using System.Security.Claims;

namespace Mst.Auth.Jwt;

/// <summary>
/// دریافت مقصد درخواست (Endpoint) و بررسی وجود Attribute.
///استخراج نقش‌ها و دسترسی‌های کاربر از Claims.
///مقایسه نقش‌ها و دسترسی‌های کاربر با مقادیر تعیین‌شده در Attribute.
///اگر کاربر مجوز نداشته باشد، درخواست مسدود می‌شود.
///اگر کاربر مجوز داشته باشد، درخواست ادامه پیدا می‌کند.
/// </summary>
public class RolePermissionMiddleware
{
    private readonly RequestDelegate _next;

    public RolePermissionMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task Invoke(HttpContext context)
    {
        // اگر درخواست به یک کنترلر یا اکشن هدایت شده باشد، اینجا اطلاعات مربوط به آن دریافت می‌شود
        var endpoint = context.GetEndpoint();

        if (endpoint != null)
        {
            var rolePermissionAttribute = endpoint.Metadata.GetMetadata<RolePermissionAttribute>();

            if (rolePermissionAttribute != null)
            {
                var userRoles = context.User.Claims
                    .Where(c => c.Type == ClaimTypes.Role)
                    .Select(c => c.Value)
                    .ToList();

                var userPermissions = context.User.Claims
                    .Where(c => c.Type == "Permission")
                    .Select(c => c.Value)
                    .ToList();

                var hasRequiredRole = rolePermissionAttribute.Roles.Length == 0 ||
                                      rolePermissionAttribute.Roles.Any(role => userRoles.Contains(role));

                var hasRequiredPermission = rolePermissionAttribute.Permissions.Length == 0 ||
                                            rolePermissionAttribute.Permissions.Any(permission => userPermissions.Contains(permission));

                // مسدود کردن دسترسی غیرمجاز
                if (!hasRequiredRole || !hasRequiredPermission)
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
