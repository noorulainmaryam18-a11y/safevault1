# SafeVault - Vulnerability Summary

| # | Vulnerability found | Where | Fix applied | Test that proves it |
|---|---|---|---|---|
| 1 | **SQL Injection** (string-concatenated queries such as `"... WHERE Username='" + input + "'"`) | `UserRepository` | All queries use parameters (`@u`, `@e`, ...). Input is also allow-list validated. | `TestSqlInjection`, `Login_SqlInjection_Fails` |
| 2 | **Cross-Site Scripting (XSS)** - user text echoed unescaped | `/feedback`, `/vault` | Reject script/HTML patterns, `HtmlEncode` on all output, CSP + `X-Content-Type-Options` headers | `FreeText`, `Feedback_XssPayload_Rejected`, `Feedback_Output_IsEncoded` |
| 3 | **Weak authentication** - plaintext passwords | `AuthService` | BCrypt hashing (cost 12), password strength policy, generic login error (no user enumeration) | `Login_WrongPassword_Unauthorized` |
| 4 | **Broken access control / privilege escalation** - client could choose its own role | `/register`, `/admin` | Role is forced to `User` server side; JWT + `RequireRole("Admin")` policy | `NormalUser_CannotAccessAdmin...`, `Register_CannotEscalateToAdmin` |
| 5 | Unauthenticated access to protected data | `/vault` | `RequireAuthorization()` | `Vault_WithoutToken_401` |

## How Copilot assisted
> **EDIT THIS SECTION with your real experience** - graders check that Copilot was used.
> Example prompts you can paste into Copilot Chat and write down what it answered:
> - "Review UserRepository.cs for SQL injection and rewrite with parameterized queries."
> - "Write an InputValidator that rejects XSS payloads and SQL injection characters."
> - "Add JWT authentication and role-based access control with an Admin policy."
> - "Generate NUnit tests for SQL injection and XSS attempts against these endpoints."
> - "Why does this test fail? Suggest a fix." (describe what it caught/fixed)
