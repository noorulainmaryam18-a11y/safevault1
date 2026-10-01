using Microsoft.Data.Sqlite;

namespace SafeVault;

public record User(int Id, string Username, string Email, string PasswordHash, string Role);

/// <summary>Every query is parameterized - user input is never concatenated into SQL.</summary>
public class UserRepository
{
    private readonly string _cs;
    public UserRepository(string connectionString) { _cs = connectionString; Init(); }

    private void Init()
    {
        using var c = new SqliteConnection(_cs); c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = @"CREATE TABLE IF NOT EXISTS Users(
            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL UNIQUE,
            Email TEXT NOT NULL,
            PasswordHash TEXT NOT NULL,
            Role TEXT NOT NULL DEFAULT 'User');";
        cmd.ExecuteNonQuery();
    }

    public bool AddUser(string username, string email, string passwordHash, string role = "User")
    {
        using var c = new SqliteConnection(_cs); c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "INSERT INTO Users(Username,Email,PasswordHash,Role) VALUES(@u,@e,@p,@r)";
        cmd.Parameters.AddWithValue("@u", username);
        cmd.Parameters.AddWithValue("@e", email);
        cmd.Parameters.AddWithValue("@p", passwordHash);
        cmd.Parameters.AddWithValue("@r", role);
        try { cmd.ExecuteNonQuery(); return true; }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19) { return false; } // duplicate
    }

    public User? GetByUsername(string username)
    {
        using var c = new SqliteConnection(_cs); c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT UserID,Username,Email,PasswordHash,Role FROM Users WHERE Username=@u";
        cmd.Parameters.AddWithValue("@u", username);
        using var r = cmd.ExecuteReader();
        return r.Read() ? new User(r.GetInt32(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4)) : null;
    }

    public int Count()
    {
        using var c = new SqliteConnection(_cs); c.Open();
        using var cmd = c.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM Users";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }
}
