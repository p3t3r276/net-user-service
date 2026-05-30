namespace UserService.API.Models;

public record LoginRequest(string Email = "user@example.com", string Password = "password123");
