# SafeVault - Security Summary

## 1. Threats identified and mitigations applied

| # | Threat | Where | Mitigation | Test that proves it |
|---|---|---|---|---|
| 1 | **SQL Injection** (e.g. `' OR '1'='1`, `'; DROP TABLE Users;--`) | `UserRepository` | All queries are parameterized (`@u`, `@e`, `@p`, `@r`). Inputs are also allow-list validated before reaching the database. | `TestSqlInjection`, `Login_SqlInjection_Fails`, `Register_RejectsInjectionUsername` |
| 2 | **Cross-Site Scripting (XSS)**: user text echoed back unescaped | `/feedback`, `/vault` | Script/HTML patterns are rejected, all output is `HtmlEncode`d, CSP and `X-Content-Type-Options` headers are set. | `FreeText`, `Feedback_XssPayload_Rejected`, `Feedback_Output_IsEncoded` |
| 3 | **Weak authentication**: plaintext passwords, user enumeration | `AuthService` | BCrypt hashing (cost 12), password strength policy, same generic error for unknown user and wrong password. | `Login_WrongPassword_Unauthorized` |
| 4 | **Broken access control / privilege escalation**: client choosing its own role | `/register`, `/admin` | Role is forced to `User` on the server. JWT authentication plus `RequireRole("Admin")` policy (RBAC). | `NormalUser_CannotAccessAdmin_ButCanAccessVault`, `Register_CannotEscalateToAdmin`, `Admin_CanAccessAdmin` |
| 5 | Unauthenticated access to protected data | `/vault` | `RequireAuthorization()` | `Vault_WithoutToken_401` |

## 2. Test results

Command: `dotnet test tests/SafeVault.Tests` (NUnit, .NET 10)

Result: **31 total, 31 passed, 0 failed.**

## 3. How Copilot assisted

I used GitHub Copilot Chat (Ask mode) in VS Code to review my code, one file at a time.

### 3.1 SQL injection review - `UserRepository.cs`
Prompt: "Review this file for SQL injection vulnerabilities and explain how parameterized
queries protect it."

Copilot confirmed that `AddUser` and `GetByUsername` use parameters (`@u`, `@e`, `@p`, `@r`)
instead of string concatenation, and that `Init` and `Count` contain only static SQL. It
explained that a payload such as `' OR 1=1 --` is treated as a literal value and not as part
of the WHERE clause. It also noted that the connection string itself must come from trusted
configuration and never from user input. No code change was needed, and I confirmed the
behaviour with my own injection tests in `TestSqlInjection.cs`.

### 3.2 Authentication and RBAC review - `Program.cs`
Prompt: "Review the authentication and role-based access control in this file and suggest
security improvements."

Copilot confirmed that the core flow is sound: authentication runs before authorization,
`/vault` requires a valid token, `/admin` requires the `AdminOnly` policy, registration always
assigns the `User` role, and JWT issuer, audience, lifetime and signing key are validated. It
also flagged these risks:

1. A predictable fallback JWT key (critical): **applied** - the app now refuses to start
   outside Development without `Jwt:Key`, and rejects keys shorter than 32 characters.
2. No HTTPS enforcement (high): **applied** - HSTS and HTTPS redirection are enabled outside
   Development.
3. Admin password seeding, no token revocation, and no brute-force protection on `/login`
   (medium): **not applied yet**. Planned improvements are a secret store for the seed
   password, shorter-lived tokens with refresh rotation, and rate limiting on `/login`.

After the changes I re-ran `dotnet test`: 31 of 31 tests still pass.

### 3.3 XSS review - `InputValidator.cs`
Prompt: "Check this for XSS bypasses and suggest improvements."

Copilot judged the code reasonably defensive for `/feedback` and `/vault`, because values are
encoded before they are returned or displayed, but it pointed out limits:

1. The denylist regex (`SuspiciousRx`) cannot cover every HTML, SVG, CSS, URL or JavaScript
   attack form, so it must not be the primary XSS defence. I agree: the real protection is
   output encoding plus the Content-Security-Policy; the regex is an extra layer that also
   rejects obviously malicious input early.
2. `HtmlEncode` is only correct for HTML text, not for attributes, JavaScript, CSS or URLs.
   Currently the app only returns HTML-text values, but any new output context needs its own
   encoder.
3. Encoding inside a JSON response can cause double encoding. Copilot recommends returning
   the original validated text and encoding only at the HTML rendering step. I kept the
   current behaviour for now because my test `Feedback_Output_IsEncoded` and the API are built
   on it; changing it is a planned improvement.
4. Add an explicit length check before the username regex and a request-body size limit
   (planned).

**Applied:** I strengthened the CSP with `base-uri 'self'` and `frame-ancestors 'none'`, and
re-ran `dotnet test` (31 of 31 pass). **Planned:** more XSS payload tests (event handlers,
SVG, CSS, URL schemes, HTML entities), body-size limits, and moving encoding to the rendering
layer.

## 4. Debugging a test failure

When I first ran the tests, 5 of 31 failed with `PipeWriter ... does not implement
UnflushedBytes`, and the endpoints returned HTTP 500. The cause was a runtime mismatch: the
project targeted .NET 8 but only the .NET 10 runtime was installed, so the test host ran the
web app on a different runtime than the one it was built for. I upgraded both projects and the
package versions to .NET 10, and all 31 tests passed.