# SafeVault

Secure ASP.NET Core 8 demo: input validation, SQL-injection prevention, XSS defence,
JWT authentication and role-based access control (RBAC). See `SECURITY_SUMMARY.md`.

## Run
```
cd src/SafeVault
dotnet run
```
Set `Seed:AdminPassword` (e.g. `dotnet user-secrets` or env var `Seed__AdminPassword`) to create the `admin` account.

## Test
```
dotnet test
```
Endpoints: `POST /register`, `POST /login`, `POST /feedback`, `GET /vault` (any logged-in user), `GET /admin` (Admin only).
