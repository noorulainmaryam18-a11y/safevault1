using System.Net;
using System.Net.Mail;
using System.Text.RegularExpressions;

namespace SafeVault;

/// <summary>Allow-list input validation + output encoding (SQLi / XSS defence in depth).</summary>
public static class InputValidator
{
    private static readonly Regex UsernameRx = new(@"^[A-Za-z0-9_]{3,30}$", RegexOptions.Compiled);
    private static readonly Regex SuspiciousRx = new(
        @"(<\s*/?\s*(script|iframe|object|embed|img|svg|style)|javascript\s*:|on\w+\s*=|--|;|/\*|\*/|\b(union|select|insert|update|delete|drop|alter|exec)\b)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static bool IsValidUsername(string? v) => v is not null && UsernameRx.IsMatch(v);

    public static bool IsValidEmail(string? v)
    {
        if (string.IsNullOrWhiteSpace(v) || v.Length > 254) return false;
        if (v.IndexOfAny(new[] { '<', '>', '"', '\'', ';', ' ' }) >= 0) return false;
        try { return new MailAddress(v).Address == v; } catch { return false; }
    }

    public static bool IsValidPassword(string? v) =>
        v is not null && v.Length is >= 8 and <= 100
        && v.Any(char.IsUpper) && v.Any(char.IsLower) && v.Any(char.IsDigit);

    /// <summary>Free text (e.g. feedback): reject known attack patterns, length-limit.</summary>
    public static bool IsSafeText(string? v, int maxLen = 500) =>
        !string.IsNullOrWhiteSpace(v) && v.Length <= maxLen && !SuspiciousRx.IsMatch(v);

    /// <summary>Always encode before echoing user data back into HTML/JSON UI.</summary>
    public static string Encode(string v) => WebUtility.HtmlEncode(v);
}
