using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Mst.Auth.Jwt;

public static class JwtServiceBootstrapper
{
    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, IConfiguration configuration, string sectionName)
    {
        services.AddSingleton<JwtSettings>();

        var jwtSettingsSection = configuration.GetSection(sectionName);
        services.Configure<JwtSettings>(jwtSettingsSection);

        var jwtSettings = jwtSettingsSection.Get<JwtSettings>();
        var key = Encoding.UTF8.GetBytes(jwtSettings.SecretKey);

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = jwtSettings.Issuer,
                ValidAudience = jwtSettings.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(key)
            };
            options.SaveToken = true;
        });

        services.AddScoped<JwtService>();

        return services;
    }
}
