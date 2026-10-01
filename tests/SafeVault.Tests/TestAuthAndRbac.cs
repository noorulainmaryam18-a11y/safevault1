using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using NUnit.Framework;

namespace SafeVault.Tests;

[TestFixture]
public class TestAuthAndRbac
{
    private WebApplicationFactory<Program> _factory = null!;
    private HttpClient _client = null!;
    private string _db = "";

    [SetUp]
    public void Setup()
    {
        _db = Path.Combine(Path.GetTempPath(), $"svi_{Guid.NewGuid():N}.db");
        _factory = new WebApplicationFactory<Program>().WithWebHostBuilder(b =>
        {
            b.UseSetting("ConnectionStrings:Default", $"Data Source={_db}");
            b.UseSetting("Seed:AdminPassword", "AdminPassw0rd");
        });
        _client = _factory.CreateClient();
    }

    [TearDown]
    public void Cleanup()
    {
        _client.Dispose(); _factory.Dispose();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        if (File.Exists(_db)) File.Delete(_db);
    }

    private async Task<string> TokenAsync(string u, string p)
    {
        var res = await _client.PostAsJsonAsync("/login", new { username = u, password = p });
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        return (await res.Content.ReadFromJsonAsync<Dictionary<string, string>>())!["token"];
    }

    private HttpRequestMessage Get(string url, string token)
    {
        var r = new HttpRequestMessage(HttpMethod.Get, url);
        r.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return r;
    }

    [Test]
    public async Task Register_RejectsInjectionUsername()
    {
        var res = await _client.PostAsJsonAsync("/register",
            new { username = "a'; DROP TABLE Users;--", email = "a@b.com", password = "Passw0rdOK" });
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Login_SqlInjection_Fails()
    {
        var res = await _client.PostAsJsonAsync("/login", new { username = "' OR '1'='1", password = "x" });
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Login_WrongPassword_Unauthorized()
    {
        var res = await _client.PostAsJsonAsync("/login", new { username = "admin", password = "nope" });
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task Vault_WithoutToken_401()
        => Assert.That((await _client.GetAsync("/vault")).StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));

    [Test]
    public async Task NormalUser_CannotAccessAdmin_ButCanAccessVault()
    {
        await _client.PostAsJsonAsync("/register",
            new { username = "bob", email = "bob@x.com", password = "Passw0rdOK" });
        var t = await TokenAsync("bob", "Passw0rdOK");
        Assert.That((await _client.SendAsync(Get("/admin", t))).StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        Assert.That((await _client.SendAsync(Get("/vault", t))).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Admin_CanAccessAdmin()
    {
        var t = await TokenAsync("admin", "AdminPassw0rd");
        Assert.That((await _client.SendAsync(Get("/admin", t))).StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Register_CannotEscalateToAdmin()
    {
        await _client.PostAsJsonAsync("/register",
            new { username = "eve", email = "eve@x.com", password = "Passw0rdOK", role = "Admin" });
        var t = await TokenAsync("eve", "Passw0rdOK");
        Assert.That((await _client.SendAsync(Get("/admin", t))).StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public async Task Feedback_XssPayload_Rejected()
    {
        var res = await _client.PostAsJsonAsync("/feedback", new { message = "<script>alert('xss')</script>" });
        Assert.That(res.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task Feedback_Output_IsEncoded()
    {
        var res = await _client.PostAsJsonAsync("/feedback", new { message = "I <3 this & that" });
        var body = await res.Content.ReadAsStringAsync();
        Assert.That(body, Does.Not.Contain("<3"));
    }
}
