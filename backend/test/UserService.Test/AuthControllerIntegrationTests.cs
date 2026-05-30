using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Shouldly;

namespace UserService.Test;

[TestClass]
public class AuthControllerIntegrationTests
{
    public TestContext TestContext { get; set; }

    private static WebApplicationFactory<Program> _factory = null!;

    private static HttpClient _client = null!;

    [ClassInitialize]
    public static void ClassInit(TestContext _)
    {
        _factory = new WebApplicationFactory<Program>();
        _client = _factory.CreateClient();
    }

    [ClassCleanup]
    public static void ClassCleanup()
    {
        _client.Dispose();
        _factory.Dispose();
    }

    // helper: login and return bearer token
    private static async Task<string> LoginAsync(string email, string password)
    {
        var response = await _client.PostAsJsonAsync("/api/auth/login", new { Email = email, Password = password });
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();

        return body.GetProperty("token").GetString()!;
    }

    private static HttpClient AuthorizedClient(string token)
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    /// --- LOGIN TESTS ---
    [TestMethod]
    public async Task Login_ValidAdmin_Returns200WithToken()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/auth/login", new { Email = "admin@co.com", Password = "admin123" }, cancellationToken: TestContext.CancellationToken);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        body.GetProperty("token").GetString().ShouldNotBeNullOrEmpty();
        body.GetProperty("roles").EnumerateArray()
            .Select(r => r.GetString())
            .ShouldContain("Admin");
    }

    [TestMethod]
    public async Task Login_InvalidPassword_Returns401()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/auth/login", new { Email = "admin@co.com", Password = "wrong" }, cancellationToken: TestContext.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    [TestMethod]
    public async Task Login_UnknownEmail_Returns401()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/auth/login", new { Email = "ghost@co.com", Password = "any" }, cancellationToken: TestContext.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

    // --- No token ---
    [TestMethod]
    public async Task SecureEndpoint_NoToken_Returns401()
    {
        var resp = await _client.GetAsync("/api/secure/profile", TestContext.CancellationToken);
        resp.StatusCode.ShouldBe(HttpStatusCode.Unauthorized);
    }

     // --- Admin-only endpoint ---

    [TestMethod]
    [DataRow("admin@co.com",   "admin123",   HttpStatusCode.OK)]
    [DataRow("manager@co.com", "manager123", HttpStatusCode.Forbidden)]
    [DataRow("user@co.com",    "user123",    HttpStatusCode.Forbidden)]
    [DataRow("analyst@co.com", "analyst123", HttpStatusCode.Forbidden)]
    public async Task AdminEndpoint_RoleMatrix(
        string email, string password, HttpStatusCode expected)
    {
        var token  = await LoginAsync(email, password);
        var client = AuthorizedClient(token);

        var response = await client.GetAsync("/api/secure/admin", TestContext.CancellationToken);
        response.StatusCode.ShouldBe(expected);
    }

    // --- Admin or Manager endpoint ---

    [TestMethod]
    [DataRow("admin@co.com",   "admin123",   HttpStatusCode.OK)]
    [DataRow("manager@co.com", "manager123", HttpStatusCode.OK)]
    [DataRow("user@co.com",    "user123",    HttpStatusCode.Forbidden)]
    [DataRow("analyst@co.com", "analyst123", HttpStatusCode.Forbidden)]
    public async Task ManagementEndpoint_RoleMatrix(
        string email, string password, HttpStatusCode expected)
    {
        var token  = await LoginAsync(email, password);
        var client = AuthorizedClient(token);

        var response = await client.GetAsync("/api/secure/management", TestContext.CancellationToken);
        response.StatusCode.ShouldBe(expected);
    }

    // --- Reports endpoint (Admin, Manager, Analyst) ---

    [TestMethod]
    [DataRow("admin@co.com",   "admin123",   HttpStatusCode.OK)]
    [DataRow("manager@co.com", "manager123", HttpStatusCode.OK)]
    [DataRow("analyst@co.com", "analyst123", HttpStatusCode.OK)]
    [DataRow("user@co.com",    "user123",    HttpStatusCode.Forbidden)]
    public async Task ReportsEndpoint_RoleMatrix(
        string email, string password, HttpStatusCode expected)
    {
        var token  = await LoginAsync(email, password);
        var client = AuthorizedClient(token);

        var response = await client.GetAsync("/api/secure/reports", TestContext.CancellationToken);
        response.StatusCode.ShouldBe(expected);
    }

    // --- Profile returns embedded roles ---

    [TestMethod]
    public async Task Profile_AdminUser_ReturnsMultipleRolesInBody()
    {
        var token  = await LoginAsync("admin@co.com", "admin123");
        var client = AuthorizedClient(token);

        var response = await client.GetAsync("/api/secure/profile", TestContext.CancellationToken);
        var body = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.CancellationToken);

        response.StatusCode.ShouldBe(HttpStatusCode.OK);
        var roles = body.GetProperty("roles")
            .EnumerateArray()
            .Select(r => r.GetString()!)
            .ToList();

        roles.ShouldContain("Admin");
        roles.ShouldContain("Manager");
    }
}
