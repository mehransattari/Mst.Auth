﻿using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace Mst.Auth.Jwt;

public static class JwtServiceBootstrapper
{
    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services, 
                                                          IConfiguration configuration,
                                                          string jwtSettingSection)
    {
        SetJwtConfig(services, configuration, jwtSettingSection);
        return services;
    }
    public static IServiceCollection AddJwtAuthentication(this IServiceCollection services,
                                                          IConfiguration configuration,
                                                          string jwtSettingSection,
                                                          string rolePermissionConfig)
    {
        services.AddSingleton<RolePermissionConfig>();
        var _rolePermissionConfig = configuration.GetSection(rolePermissionConfig);
        services.Configure<RolePermissionConfig>(_rolePermissionConfig);

        SetJwtConfig(services, configuration, jwtSettingSection);
        return services;
    }
    private static void SetJwtConfig(IServiceCollection services, IConfiguration configuration, string jwtSettingSection)
    {
        services.AddSingleton<JwtSettings>();
        var jwtSettingsSection = configuration.GetSection(jwtSettingSection);
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
            options.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = context =>
                {
                    Console.WriteLine("Authentication failed: " + context.Exception.Message);
                    return Task.CompletedTask;
                },
                OnTokenValidated = context =>
                {
                    Console.WriteLine("Token validated: " + context.SecurityToken);
                    return Task.CompletedTask;
                }
            };
        });

        services.AddScoped<JwtService>();
    }
       
    public static IApplicationBuilder UseRolePermissionsAccess(this IApplicationBuilder app)
    {
        return app.UseMiddleware<RolePermissionMiddleware>();
    }
}
