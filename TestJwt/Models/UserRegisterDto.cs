namespace TestJwt.Models;

public class UserRegisterDto
{
    public string Username { get; set; }
    public string Password { get; set; }
    public string Role { get; set; } // برای تعیین نقش کاربر
}
