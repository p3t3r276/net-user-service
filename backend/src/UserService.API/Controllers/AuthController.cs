using Microsoft.AspNetCore.Mvc;
using UserService.API.Models;
using UserService.API.Services;

namespace UserService.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IJwtService jwtService) : ControllerBase
{
    private readonly IJwtService _jwtService = jwtService;

    // Fake user store — replace with real DB lookup
    private static readonly Dictionary<string, (string Password, string[] Roles)> Users = new()
    {
        ["admin@co.com"]   = ("admin123",   ["Admin", "Manager"]),
        ["manager@co.com"] = ("manager123", ["Manager"]),
        ["user@co.com"]    = ("user123",    ["User"]),
        ["analyst@co.com"] = ("analyst123", ["Analyst"]),
    };

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        if (!Users.TryGetValue(request.Email, out var user) ||
            user.Password != request.Password)
            return Unauthorized(new { message = "Invalid credentials" });

        var token = _jwtService.GenerateToken(
            Guid.NewGuid().ToString(), request.Email, user.Roles);

        return Ok(new { token, roles = user.Roles });
    }
}
