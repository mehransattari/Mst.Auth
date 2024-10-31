using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Mst.Auth.Jwt;
using TestJwt.Data;
using TestJwt.Models;
using BCrypt.Net;
namespace TestJwt.Controllers;

[Route("api/[controller]")]
[ApiController]
[Authorize]
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
            return Unauthorized("رفرش توکن نامعتبر یا منقضی شده است.");

        var principal = _jwtService.GetPrincipalFromExpiredToken(refreshTokenDto.Token);
        if (principal == null)
            return BadRequest("توکن نامعتبر است.");

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
            return Unauthorized("نام کاربری یا رمز عبور اشتباه است");

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
            return BadRequest("نام کاربری قبلاً ثبت شده است.");

        var user = new User
        {
            Username = registerDto.Username,
            Password = BCrypt.Net.BCrypt.HashPassword(registerDto.Password), // هش کردن پسورد
            Role = registerDto.Role,
            RefreshToken = _jwtService.GenerateRefreshToken(),
            RefreshTokenExpiryTime = DateTime.Now.AddDays(_jwtSettings.RefreshTokenExpiryDays)
        };

        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return CreatedAtAction(nameof(GetUser), new { id = user.Id }, user);
    }

}
