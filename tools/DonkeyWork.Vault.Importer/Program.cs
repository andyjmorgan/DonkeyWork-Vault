// One-time importer: copy OAuth provider configs + tokens from the agents DB into the vault,
// decrypting the agents' AES-CBC blobs and re-encrypting with the vault envelope cipher.
// Secrets are never printed. Configure via env:
//   AGENTS_DB, AGENTS_KEY (raw Persistence:EncryptionKey), VAULT_DB, VAULT_KEK (base64 32 bytes, kek v1)
using System.Security.Cryptography;
using System.Text;
using DonkeyWork.Vault.Core.Crypto;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;

static string Env(string k) => Environment.GetEnvironmentVariable(k)
    ?? throw new InvalidOperationException($"missing env {k}");

var agentsDb = Env("AGENTS_DB");
var vaultDb = Env("VAULT_DB");
var aesKey = SHA256.HashData(Encoding.UTF8.GetBytes(Env("AGENTS_KEY")));

string Dec(byte[] blob)
{
    using var aes = Aes.Create();
    aes.Key = aesKey;
    aes.IV = blob[..16];
    using var dec = aes.CreateDecryptor();
    return Encoding.UTF8.GetString(dec.TransformFinalBlock(blob, 16, blob.Length - 16));
}

IEnvelopeCipher cipher = new EnvelopeCipherService(new LocalKekProvider(Options.Create(new VaultCryptoOptions
{
    ActiveKekId = "v1",
    Keks = new() { ["v1"] = Env("VAULT_KEK") },
})));

var configs = new List<(Guid uid, string prov, string cid, string cs, string? scopes, string? redirect)>();
var tokens = new List<(Guid uid, string prov, string account, string at, string rt, string? scopes, DateTimeOffset? exp)>();

await using (var ac = new NpgsqlConnection(agentsDb))
{
    await ac.OpenAsync();

    await using (var cmd = new NpgsqlCommand(
        "select \"UserId\",\"Provider\",\"ClientIdEncrypted\",\"ClientSecretEncrypted\",\"ScopesJson\",\"RedirectUri\" from credentials.oauth_provider_configs", ac))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            configs.Add((r.GetGuid(0), r.GetString(1), Dec((byte[])r[2]), Dec((byte[])r[3]),
                r.IsDBNull(4) ? null : r.GetFieldValue<string>(4),
                r.IsDBNull(5) ? null : r.GetString(5)));
        }
    }

    await using (var cmd = new NpgsqlCommand(
        "select \"UserId\",\"Provider\",coalesce(\"Email\",\"ExternalUserId\",''),\"AccessTokenEncrypted\",\"RefreshTokenEncrypted\",\"ScopesJson\",\"ExpiresAt\" from credentials.oauth_tokens", ac))
    await using (var r = await cmd.ExecuteReaderAsync())
    {
        while (await r.ReadAsync())
        {
            tokens.Add((r.GetGuid(0), r.GetString(1), r.GetString(2), Dec((byte[])r[3]),
                r.IsDBNull(4) ? "" : Dec((byte[])r[4]),
                r.IsDBNull(5) ? null : r.GetFieldValue<string>(5),
                r.IsDBNull(6) ? null : r.GetFieldValue<DateTimeOffset>(6)));
        }
    }
}

var opts = new DbContextOptionsBuilder<VaultDbContext>()
    .UseNpgsql(vaultDb, n => n.MigrationsHistoryTable("__ef_migrations_history", "vault"))
    .Options;
await using var db = new VaultDbContext(opts, caller: null);

await db.OAuthProviderConfigs.IgnoreQueryFilters().ExecuteDeleteAsync();
await db.OAuthTokens.IgnoreQueryFilters().ExecuteDeleteAsync();

foreach (var c in configs)
{
    db.OAuthProviderConfigs.Add(new OAuthProviderConfigEntity
    {
        UserId = c.uid,
        ProviderKey = c.prov.ToLowerInvariant(),
        ClientIdCipher = cipher.EncryptString(c.cid),
        ClientSecretCipher = cipher.EncryptString(c.cs),
        ScopesJson = c.scopes,
        RedirectUri = c.redirect,
    });
}
foreach (var t in tokens)
{
    db.OAuthTokens.Add(new OAuthTokenEntity
    {
        UserId = t.uid,
        ProviderKey = t.prov.ToLowerInvariant(),
        Account = t.account,
        AccessTokenCipher = cipher.EncryptString(t.at),
        RefreshTokenCipher = t.rt.Length > 0 ? cipher.EncryptString(t.rt) : [],
        ScopesJson = t.scopes,
        ExpiresAt = t.exp,
    });
}

await db.SaveChangesAsync();
Console.WriteLine($"Imported {configs.Count} provider configs and {tokens.Count} tokens into the vault.");
