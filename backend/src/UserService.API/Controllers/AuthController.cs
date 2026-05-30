using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using UserService.API.Services;

namespace UserService.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(IJwtService jwtService) : ControllerBase
{
    private readonly IJwtService _jwtService = jwtService;

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // Replace with real user lookup + password hash check
        if (request.Email == "user@example.com" && request.Password == "password123")
        {
            var token = _jwtService.GenerateToken("user-1", request.Email, ["User"]);
            return Ok(new { token });
        }
        return Unauthorized(new { message = "Invalid credentials" });
    }
}
