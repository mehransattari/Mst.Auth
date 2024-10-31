
using Microsoft.EntityFrameworkCore;
using TestJwt.Models;
namespace TestJwt.Data;

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
                Password = BCrypt.Net.BCrypt.HashPassword("admin123"), // هش رمز عبور
                Role = "Admin",
                RefreshToken = Guid.NewGuid().ToString(), // مقدار پیش‌فرض برای RefreshToken
                RefreshTokenExpiryTime = DateTime.Now.AddDays(7) // تاریخ انقضا برای RefreshToken
            },
            new User
            {
                Id = 2,
                Username = "user",
                Password = BCrypt.Net.BCrypt.HashPassword("user123"), // هش رمز عبور
                Role = "User",
                RefreshToken = Guid.NewGuid().ToString(), // مقدار پیش‌فرض برای RefreshToken
                RefreshTokenExpiryTime = DateTime.Now.AddDays(7) // تاریخ انقضا برای RefreshToken
            }
        );
    }

}
