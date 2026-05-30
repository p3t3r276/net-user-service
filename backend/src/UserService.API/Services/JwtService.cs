using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Tokens;

namespace UserService.API.Services;

public class JwtService : IJwtService
{
    private readonly IConfiguration _config;
    private readonly SymmetricSecurityKey _key;

    ILogger<JwtService> _logger;

    public JwtService(ILogger<JwtService> logger, IConfiguration config)
    {
        _config = config;
        _key = new SymmetricSecurityKey(
            Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        _logger = logger;
    }

    public string GenerateToken(string userId, string email, IList<string> roles, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var claims = new List<Claim>
            {
                new(ClaimTypes.NameIdentifier, userId),
                new(ClaimTypes.Email, email),
                new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            };

            claims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            var creds = new SigningCredentials(_key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(
                    double.Parse(_config["Jwt:ExpiresInMinutes"]!)),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        catch(Exception ex)
        {
            _logger.LogError(ex, "GenerateToken-JwtService");

            throw;
        }
    }

    public ClaimsPrincipal? ValidateToken(string token, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var handler = new JwtSecurityTokenHandler();

            return handler.ValidateToken(token, new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _key,
                ValidateIssuer = true,
                ValidIssuer = _config["Jwt:Issuer"],
                ValidateAudience = true,
                ValidAudience = _config["Jwt:Audience"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            }, out _);
        }
        catch(Exception ex)
        {
            _logger.LogError(ex, "ValidateToken-JwtService");

            throw;
        }
    }
}
