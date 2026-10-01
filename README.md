# SafeVault

Secure ASP.NET Core 10 demo: input validation, SQL-injection prevention, XSS defence,
JWT authentication and role-based access control (RBAC). See `SECURITY_SUMMARY.md`.

## Requirements
- .NET 10 SDK

## Run
```
cd src/SafeVault
dotnet run
```
Set `Seed:AdminPassword` (e.g. `dotnet user-secrets` or env var `Seed__AdminPassword`) to create the `admin` account.

## Test
```
dotnet test tests/SafeVault.Tests
```
Result: 31 tests, 31 passed, 0 failed (NUnit).

## Endpoints
- `POST /register`: create a normal user (role is always `User`)
- `POST /login`: returns a JWT
- `POST /feedback`: validated and HTML-encoded text
- `GET /vault`: any logged-in user
- `GET /admin`: Admin role only