using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault;

namespace SafeVault.Tests;

[TestFixture]
public class TestSqlInjection
{
    private string _db = "";
    private UserRepository _repo = null!;

    [SetUp]
    public void Setup()
    {
        _db = Path.Combine(Path.GetTempPath(), $"sv_{Guid.NewGuid():N}.db");
        _repo = new UserRepository($"Data Source={_db}");
        _repo.AddUser("alice", "alice@x.com", AuthService.Hash("Passw0rdOK"));
    }

    [TearDown]
    public void Cleanup() { SqliteConnection.ClearAllPools(); if (File.Exists(_db)) File.Delete(_db); }

    [TestCase("' OR '1'='1")]
    [TestCase("alice' --")]
    [TestCase("'; DROP TABLE Users;--")]
    public void InjectionPayload_ReturnsNoUser_AndTableSurvives(string payload)
    {
        Assert.That(_repo.GetByUsername(payload), Is.Null);
        Assert.That(_repo.Count(), Is.EqualTo(1));          // table still exists, data intact
        Assert.That(_repo.GetByUsername("alice"), Is.Not.Null);
    }

    [Test]
    public void InjectionPayload_StoredAsLiteralText_NotExecuted()
    {
        _repo.AddUser("x'); DROP TABLE Users;--", "e@x.com", "h");
        Assert.That(_repo.Count(), Is.EqualTo(2));
    }
}
