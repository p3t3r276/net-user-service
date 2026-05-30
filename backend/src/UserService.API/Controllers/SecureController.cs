using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserService.API.Attributes;

namespace UserService.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class SecureController : ControllerBase
{
    [HttpGet("profile")]
    
    public IActionResult GetProfile()
    {
        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var email  = User.FindFirstValue(ClaimTypes.Email);
        var roles  = User.FindAll(ClaimTypes.Role).Select(c => c.Value);
        return Ok(new { userId, email, roles });
    }

    [HttpGet("admin")]
    [AuthorizeRoles("Admin")]
    public IActionResult AdminOnly() => Ok(new { area = "Admin" });

    // Multiple roles via custom attribute
    [HttpGet("management")]
    [AuthorizeRoles("Admin", "Manager")]
    public IActionResult AdminOrManager() => Ok(new { area = "Management" });

    // Policy-based (alternative approach)
    [HttpGet("staff")]
    [Authorize(Policy = "AnyStaff")]
    public IActionResult AnyStaff() => Ok(new { area = "Staff" });

    // Multiple [AuthorizeRoles] stacked = AND logic (both must match)
    // Use single attribute with multiple roles for OR logic
    [HttpGet("reports")]
    [AuthorizeRoles("Admin", "Manager", "Analyst")]
    public IActionResult Reports() => Ok(new { area = "Reports" });
}
