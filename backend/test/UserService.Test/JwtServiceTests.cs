using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Configuration;
using Shouldly;
using UserService.API.Services;
using Microsoft.Extensions.Logging.Testing;
using System.Security.Claims;

namespace UserService.Test;

[TestClass]
public sealed class JwtServiceTests
{
    public TestContext TestContext { get; set; }

    private FakeLogger<JwtService> _loggerMock;

    private readonly IJwtService _jwtService;

    public JwtServiceTests()
    {
        _loggerMock = new FakeLogger<JwtService>();
        _jwtService = new JwtService(_loggerMock, BuildConfig());
    }

    [TestMethod]
    public void GenerateToken_SingleRole_ReturnsValidJwt()
    {
        var token = _jwtService.GenerateToken("u1", "a@b.com", ["User"], TestContext.CancellationToken);

        token.ShouldNotBeNullOrEmpty();
        new JwtSecurityTokenHandler().CanReadToken(token).ShouldBeTrue();
    }

    [TestMethod]
    public void GenerateToken_MultipleRoles_AllRolesEmbedded()
    {
        // Arrange
        var roles = new[] { "Admin", "Manager", "Analyst" };
        var token = _jwtService.GenerateToken("u1", "a@b.com", roles);

        // Act
        var principal = _jwtService.ValidateToken(token);
        var tokenRoles = principal!
            .FindAll(ClaimTypes.Role)
            .Select(c => c.Value)
            .ToList();

        // Assert
        tokenRoles.ShouldBe(roles, ignoreOrder: true);
    }

    [TestMethod]
    public void ValidateToken_ValidToken_ReturnsPrincipalWithClaims()
    {
        var token = _jwtService.GenerateToken("u42", "test@x.com", ["Admin"]);
        var principal = _jwtService.ValidateToken(token);

        principal.ShouldNotBeNull();
        principal!.FindFirstValue(ClaimTypes.NameIdentifier).ShouldBe("u42");
        principal.FindFirstValue(ClaimTypes.Email).ShouldBe("test@x.com");
        principal.IsInRole("Admin").ShouldBeTrue();
    }

    [TestMethod]
    public void ValidateToken_TamperedToken_ReturnsNull()
    {
        var token = _jwtService.GenerateToken("u1", "a@b.com", ["User"], TestContext.CancellationToken);
        var tampered = token[..^5] + "XXXXX";

        _jwtService.ValidateToken(tampered, TestContext.CancellationToken).ShouldBeNull();
    }

    [TestMethod]
    public void ValidateToken_WrongKey_ReturnsNull()
    {
        // Token signed with a different key
        var otherService = new JwtService(_loggerMock, BuildConfig("wrong-key-that-is-at-least-32chars!!"));
        var token = otherService.GenerateToken("u1", "a@b.com", ["User"], TestContext.CancellationToken);

        _jwtService.ValidateToken(token, TestContext.CancellationToken).ShouldBeNull();
    }

    [TestMethod]
    public void GenerateToken_EmptyRoles_ProducesTokenWithNoneRoles()
    {
        var token = _jwtService.GenerateToken("u1", "a@b.com", [], TestContext.CancellationToken);
        var principal = _jwtService.ValidateToken(token, TestContext.CancellationToken);

        principal.ShouldNotBeNull();
        principal!.FindAll(ClaimTypes.Role).ShouldBeEmpty();
    }


    // Helper: build in-memory IConfiguration
    private static IConfiguration BuildConfig(string? key = null) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Key"] = key ?? "test-super-secret-key-at-least-32-chars!!",
                ["Jwt:Issuer"] = "https://test.com",
                ["Jwt:Audience"] = "https://test.com",
                ["Jwt:ExpiresInMinutes"] = "60"
            })
            .Build();
}
