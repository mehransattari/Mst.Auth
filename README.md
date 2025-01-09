### Install package

`Install-Package MST.Auth.Jwt -Version 1.0.1`

### Program.cs
```
builder.Services.AddJwtAuthentication(builder.Configuration, sectionName:"JwtSettings");

     app.UseAuthentication(); 
     app.UseAuthorization();  
     app.UseRolePermissionMiddleware(); 
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

### Add SwaggerGen
```
 <PackageReference Include="Swashbuckle.AspNetCore" Version="6.9.0" />

builder.Services.AddSwaggerGen(c =>  
{  
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Your API", Version = "v1" });  

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme  
    {  
        Name = "Authorization",  
        Type = SecuritySchemeType.ApiKey,  
        Scheme = "Bearer",  
        BearerFormat = "JWT",  
        In = ParameterLocation.Header,  
        Description = "Enter 'Bearer' followed by a space and your token."  
    });  

    c.AddSecurityRequirement(new OpenApiSecurityRequirement  
    {  
        {  
            new OpenApiSecurityScheme  
            {  
                Reference = new OpenApiReference  
                {  
                    Type = ReferenceType.SecurityScheme,  
                    Id = "Bearer"  
                }  
            },  
            new string[] {}  
        }  
    });  
});  

if (app.Environment.IsDevelopment())  
{  
    app.UseSwagger();  
    app.UseSwaggerUI();  
}  

app.UseAuthentication();  
app.UseAuthorization();

```


### Add DbContext
```

    <PackageReference Include="Microsoft.EntityFrameworkCore.Design" Version="8.0.0">
      <PrivateAssets>all</PrivateAssets>
      <IncludeAssets>runtime; build; native; contentfiles; analyzers; buildtransitive</IncludeAssets>
    </PackageReference>
    <PackageReference Include="Microsoft.EntityFrameworkCore" Version="8.0.0" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="8.0.0" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Tools" Version="8.0.0" />


  "ConnectionStrings": {
    "DefaultConnection": "Server=DESKTOP-AAOIHBN;Database=UserManagementDb;Trusted_Connection=True;MultipleActiveResultSets=true"
  },


builder.Services.AddDbContext<UserManagementContext>(options =>
     options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

public class User
{
    public int Id { get; set; }
    public string Username { get; set; }
    public string Password { get; set; }
    public string Role { get; set; }
    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
}


public class UserManagementContext : DbContext
{
    public UserManagementContext(DbContextOptions<UserManagementContext> options) : base(options) { }

    public DbSet<User> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>().HasData(
            new User
            {
                Id = 1,
                Username = "admin",
                Password = BCrypt.Net.BCrypt.HashPassword("admin123"), 
                Role = "Admin",
                RefreshToken = Guid.NewGuid().ToString(), 
                RefreshTokenExpiryTime = DateTime.Now.AddDays(7) 
            },
            new User
            {
                Id = 2,
                Username = "user",
                Password = BCrypt.Net.BCrypt.HashPassword("user123"), 
                Role = "User",
                RefreshToken = Guid.NewGuid().ToString(), 
                RefreshTokenExpiryTime = DateTime.Now.AddDays(7) 
            }
        );
    }

}

```


###How Use Controller

```
[Route("api/[controller]")]  
[ApiController]  
[Authorize]  
[RolePermission(roles: new[] { "Admin" }, permissions: new[] { "EditDashboard" })]
public class UsersController : ControllerBase  
{  
    private readonly UserManagementContext _context;  
    private readonly JwtService _jwtService;  
    private readonly JwtSettings _jwtSettings;  

    public UsersController(UserManagementContext context, JwtService jwtService, IOptions<JwtSettings> jwtSettings)  
    {  
        _context = context;  
        _jwtService = jwtService;  
        _jwtSettings = jwtSettings.Value;  
    }  

    [HttpGet]  
    public async Task<ActionResult<IEnumerable<User>>> GetUsers()  
    {  
        return await _context.Users.ToListAsync();  
    }  

    [HttpGet("{id}")]  
    public async Task<ActionResult<User>> GetUser(int id)  
    {  
        var user = await _context.Users.FindAsync(id);  

        if (user == null)  
            return NotFound();  

        return user;  
    }  

    [HttpPost]  
    public async Task<ActionResult<User>> PostUser(User user)  
    {  
        _context.Users.Add(user);  
        await _context.SaveChangesAsync();  

        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);  
    }  

    [HttpPost("refresh-token")]  
    [AllowAnonymous]  
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenDto refreshTokenDto)  
    {  
        var user = await _context.Users.FirstOrDefaultAsync(u => u.RefreshToken == refreshTokenDto.RefreshToken);  

        if (user == null || user.RefreshTokenExpiryTime <= DateTime.Now)  
            return Unauthorized("Invalid or expired refresh token.");  

        var principal = _jwtService.GetPrincipalFromExpiredToken(refreshTokenDto.Token);  
        if (principal == null)  
            return BadRequest("Invalid token.");  

        var newJwtToken = _jwtService.GenerateToken(user.Id.ToString(), user.Role);  
        var newRefreshToken = _jwtService.GenerateRefreshToken();  

        user.RefreshToken = newRefreshToken;  
        user.RefreshTokenExpiryTime = DateTime.Now.AddDays(_jwtSettings.RefreshTokenExpiryDays);  
        await _context.SaveChangesAsync();  

        return Ok(new { Token = newJwtToken, RefreshToken = newRefreshToken });  
    }  

    [HttpPost("login")]  
    [AllowAnonymous]  
    public async Task<IActionResult> Login([FromBody] UserLoginDto loginDto)  
    {  
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == loginDto.Username);  

        if (user == null || !BCrypt.Net.BCrypt.Verify(loginDto.Password, user.Password))  
            return Unauthorized("Incorrect username or password.");  

        var token = _jwtService.GenerateToken(user.Id.ToString(), user.Role);  
        var refreshToken = _jwtService.GenerateRefreshToken();  

        user.RefreshToken = refreshToken;  
        user.RefreshTokenExpiryTime = DateTime.Now.AddDays(_jwtSettings.RefreshTokenExpiryDays);  
        await _context.SaveChangesAsync();  

        return Ok(new { Token = token, RefreshToken = refreshToken });  
    }  

    [HttpPost("register")]  
    [AllowAnonymous]  
    public async Task<ActionResult<User>> Register([FromBody] UserRegisterDto registerDto)  
    {  
        if (await _context.Users.AnyAsync(u => u.Username == registerDto.Username))  
            return BadRequest("Username is already taken.");  

        var user = new User  
        {  
            Username = registerDto.Username,  
            Password = BCrypt.Net.BCrypt.HashPassword(registerDto.Password), // Hashing password  
            Role = registerDto.Role,  
            RefreshToken = _jwtService.GenerateRefreshToken(),  
            RefreshTokenExpiryTime = DateTime.Now.AddDays(_jwtSettings.RefreshTokenExpiryDays)  
        };  

        _context.Users.Add(user);  
        await _context.SaveChangesAsync();  

        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);  
    }  
}

```


