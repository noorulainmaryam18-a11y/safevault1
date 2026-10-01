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