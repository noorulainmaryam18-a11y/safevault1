using NUnit.Framework;
using SafeVault;

namespace SafeVault.Tests;

[TestFixture]
public class TestInputValidation
{
    [TestCase("alice_01", true)]
    [TestCase("ab", false)]
    [TestCase("bob'; DROP TABLE Users;--", false)]
    [TestCase("' OR '1'='1", false)]
    [TestCase("<script>alert(1)</script>", false)]
    public void Username(string input, bool ok) => Assert.That(InputValidator.IsValidUsername(input), Is.EqualTo(ok));

    [TestCase("a@b.com", true)]
    [TestCase("a@b.com<script>", false)]
    [TestCase("not-an-email", false)]
    public void Email(string input, bool ok) => Assert.That(InputValidator.IsValidEmail(input), Is.EqualTo(ok));

    [TestCase("Passw0rdOK", true)]
    [TestCase("short1A", false)]
    [TestCase("alllowercase1", false)]
    public void Password(string input, bool ok) => Assert.That(InputValidator.IsValidPassword(input), Is.EqualTo(ok));

    [TestCase("Great app!", true)]
    [TestCase("<script>alert('xss')</script>", false)]
    [TestCase("<img src=x onerror=alert(1)>", false)]
    [TestCase("javascript:alert(1)", false)]
    [TestCase("1; DROP TABLE Users", false)]
    [TestCase("x' UNION SELECT * FROM Users--", false)]
    public void FreeText(string input, bool ok) => Assert.That(InputValidator.IsSafeText(input), Is.EqualTo(ok));

    [Test]
    public void Encode_NeutralisesHtml() =>
        Assert.That(InputValidator.Encode("<b>hi</b>"), Does.Not.Contain("<"));
}
