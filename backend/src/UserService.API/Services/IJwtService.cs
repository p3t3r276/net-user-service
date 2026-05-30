using System.Security.Claims;

namespace UserService.API.Services;

public interface IJwtService
{
    string GenerateToken(string userId, string email, IList<string> roles, CancellationToken cancellationToken = default);

    ClaimsPrincipal? ValidateToken(string token, CancellationToken cancellationToken = default);
}
