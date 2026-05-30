using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace UserService.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class SecureController : ControllerBase
{
    [HttpGet("profile")]
    public IActionResult GetProfile()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var email  = User.FindFirstValue(ClaimTypes.Email);
        return Ok(new { userId, email });
    }

    [HttpGet("admin")]
    [Authorize(Roles = "Admin")]
    public IActionResult AdminOnly() => Ok("Admin area");
}
