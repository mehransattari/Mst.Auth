### Install package

`Install-Package MST.Auth.Jwt -Version 1.0.7`

### Program.cs
```
// سرویس JWT
builder.Services
    .AddJwtAuthentication(builder.Configuration, 
                          jwtSettingSection: nameof(JwtSettings), 
                          rolePermissionConfig: nameof(RolePermissionConfig));

  app.UseAuthentication(); 
  app.UseAuthorization();
  app.UseRolePermissionsAccess();
```
                             


### Add appsetting.json
```
  "JwtSettings": {
    "SecretKey": "YourVerySecretKeyThatIsAtLeast32CharactersLong!",
    "Issuer": "YourIssuer",
    "Audience": "YourAudience",
    "ExpiryMinutes": 1,
    "RefreshTokenExpiryDays": 7
  }

  "RolePermissionConfig": {
    "ProtectedEndpoints": [
      //{
      //  "Path": "/api/v1/user",
      //  "Roles": [ "normalUser" ],
      //  "Permissions": [ "Create" ]
      //},
      //{
      //  "Path": "/api/v1/role",
      //  "Roles": [ "admin" ],
      //  "Permissions": [ "Create,Edit" ]
      //},
    ],
    "ExcludedPaths": [ "/api/v1/user/login", "/api/v1/user/register" ]
  }
```

###Add Dtos

```


public class RefreshTokenDto
{
    public string Token { get; set; }
    public string RefreshToken { get; set; }
}


public class UserLoginDto
{
    public string Username { get; set; }
    public string Password { get; set; }
}

public class UserRegisterDto
{
    public string Username { get; set; }
    public string Password { get; set; }
    public string Role { get; set; } 
}

```


###How Use Controller

```
[ApiVersion(1, Deprecated = false)]
[ApiVersion(2)]
[Authorize]
[Route("api/v{v:apiVersion}/[controller]")]
public class UserController : ControllerBase
{
}
```


