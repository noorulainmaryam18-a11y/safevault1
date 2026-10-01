using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using SafeVault;

var builder = WebApplication.CreateBuilder(args);

var jwtKey = builder.Configuration["Jwt:Key"] ?? "dev-only-key-change-in-production-0123456789";
var cs = builder.Configuration["ConnectionStrings:Default"] ?? "Data Source=safevault.db";

var repo = new UserRepository(cs);
var auth = new AuthService(repo, jwtKey);
builder.Services.AddSingleton(repo);
builder.Services.AddSingleton(auth);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o => o.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true, ValidIssuer = AuthService.Issuer,
        ValidateAudience = true, ValidAudience = AuthService.Audience,
        ValidateLifetime = true, ValidateIssuerSigningKey = true,
        IssuerSigningKey = AuthService.MakeKey(jwtKey)
    });
builder.Services.AddAuthorization(o =>
    o.AddPolicy("AdminOnly", p => p.RequireRole("Admin")));

var app = builder.Build();

// Optional admin seed (admin accounts can never be self-registered).
var seedPw = app.Configuration["Seed:AdminPassword"];
if (!string.IsNullOrEmpty(seedPw) && repo.GetByUsername("admin") is null)
    repo.AddUser("admin", "admin@safevault.local", AuthService.Hash(seedPw), "Admin");

// Security headers (XSS / clickjacking mitigation)
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'";
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    await next();
});

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", (RegisterRequest r) =>
{
    if (!InputValidator.IsValidUsername(r.Username)) return Results.BadRequest("Invalid username.");
    if (!InputValidator.IsValidEmail(r.Email)) return Results.BadRequest("Invalid email.");
    if (!InputValidator.IsValidPassword(r.Password)) return Results.BadRequest("Weak password.");
    // Role is ALWAYS "User" - never taken from client input.
    return repo.AddUser(r.Username, r.Email, AuthService.Hash(r.Password), "User")
        ? Results.Ok("Registered.") : Results.Conflict("Username already exists.");
});

app.MapPost("/login", (LoginRequest r) =>
{
    if (!InputValidator.IsValidUsername(r.Username) || string.IsNullOrEmpty(r.Password))
        return Results.Unauthorized();
    var token = auth.Login(r.Username, r.Password);
    return token is null ? Results.Unauthorized() : Results.Ok(new { token });
});

app.MapPost("/feedback", (FeedbackRequest r) =>
{
    if (!InputValidator.IsSafeText(r.Message)) return Results.BadRequest("Invalid input.");
    return Results.Ok(new { message = InputValidator.Encode(r.Message) });
});

app.MapGet("/vault", (System.Security.Claims.ClaimsPrincipal u) =>
    Results.Ok($"Welcome {InputValidator.Encode(u.Identity!.Name!)}, this is your vault."))
    .RequireAuthorization();

app.MapGet("/admin", () => Results.Ok("Admin dashboard."))
    .RequireAuthorization("AdminOnly");

app.Run();

public record RegisterRequest(string Username, string Email, string Password);
public record LoginRequest(string Username, string Password);
public record FeedbackRequest(string Message);
public partial class Program { }
