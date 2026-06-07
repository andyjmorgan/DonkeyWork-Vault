// Reads OAuth provider configs + tokens from the agents DB, decrypting the agents' AES-CBC
// blobs. Then, depending on env:
//   EXPORT_FILE set  -> writes the decrypted connections to a local JSON file (back up / keep)
//   VAULT_DB set     -> re-encrypts with the vault envelope cipher and upserts into the vault
// Secrets are never printed. Env: AGENTS_DB, AGENTS_KEY, [EXPORT_FILE], [VAULT_DB, VAULT_KEK]
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DonkeyWork.Vault.Core.Crypto;
using DonkeyWork.Vault.Persistence;
using DonkeyWork.Vault.Persistence.Entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Npgsql;

static string Env(string k) => Environment.GetEnvironmentVariable(k) ?? throw new InvalidOperationException($"missing env {k}");
static string? EnvOpt(string k) => Environment.GetEnvironmentVariable(k);

var agentsDb = Env("AGENTS_DB");
var aesKey = SHA256.HashData(Encoding.UTF8.GetBytes(Env("AGENTS_KEY")));

string Dec(byte[] blob)
{
    using var aes = Aes.Create();
    aes.Key = aesKey;
    aes.IV = blob[..16];
    using var dec = aes.CreateDecryptor();
    return Encoding.UTF8.GetString(dec.TransformFinalBlock(blob, 16, blob.Length - 16));
}

var configs = new List<Dictionary<string, string?>>();
var tokens = new List<Dictionary<string, string?>>();

await using (var ac = new NpgsqlConnection(agentsDb))
{
    await ac.OpenAsync();
    await using (var cmd = new NpgsqlCommand("select \"UserId\",\"Provider\",\"ClientIdEncrypted\",\"ClientSecretEncrypted\",\"ScopesJson\",\"RedirectUri\" from credentials.oauth_provider_configs", ac))
    await using (var r = await cmd.ExecuteReaderAsync())
        while (await r.ReadAsync())
            configs.Add(new() {
                ["userId"] = r.GetGuid(0).ToString(), ["provider"] = r.GetString(1).ToLowerInvariant(),
                ["clientId"] = Dec((byte[])r[2]), ["clientSecret"] = Dec((byte[])r[3]),
                ["scopesJson"] = r.IsDBNull(4) ? null : r.GetFieldValue<string>(4), ["redirectUri"] = r.IsDBNull(5) ? null : r.GetString(5),
            });

    await using (var cmd = new NpgsqlCommand("select \"UserId\",\"Provider\",coalesce(\"Email\",\"ExternalUserId\",''),\"AccessTokenEncrypted\",\"RefreshTokenEncrypted\",\"ScopesJson\",\"ExpiresAt\" from credentials.oauth_tokens", ac))
    await using (var r = await cmd.ExecuteReaderAsync())
        while (await r.ReadAsync())
            tokens.Add(new() {
                ["userId"] = r.GetGuid(0).ToString(), ["provider"] = r.GetString(1).ToLowerInvariant(), ["account"] = r.GetString(2),
                ["accessToken"] = Dec((byte[])r[3]), ["refreshToken"] = r.IsDBNull(4) ? null : Dec((byte[])r[4]),
                ["scopesJson"] = r.IsDBNull(5) ? null : r.GetFieldValue<string>(5),
                ["expiresAt"] = r.IsDBNull(6) ? null : r.GetFieldValue<DateTimeOffset>(6).ToString("o"),
            });
}

if (EnvOpt("EXPORT_FILE") is { } exportFile)
{
    var json = JsonSerializer.Serialize(new { configs, tokens }, new JsonSerializerOptions { WriteIndented = true });
    await File.WriteAllTextAsync(exportFile, json);
    Console.WriteLine($"Exported {configs.Count} configs and {tokens.Count} tokens to {exportFile}");
}

if (EnvOpt("VAULT_DB") is { } vaultDb)
{
    IEnvelopeCipher cipher = new EnvelopeCipherService(new LocalKekProvider(Options.Create(new VaultCryptoOptions
    {
        ActiveKekId = "v1",
        Keks = new() { ["v1"] = Env("VAULT_KEK") },
    })));
    var opts = new DbContextOptionsBuilder<VaultDbContext>().UseNpgsql(vaultDb, n => n.MigrationsHistoryTable("__ef_migrations_history", "vault")).Options;
    await using var db = new VaultDbContext(opts, caller: null);
    await db.OAuthProviderConfigs.IgnoreQueryFilters().ExecuteDeleteAsync();
    await db.OAuthTokens.IgnoreQueryFilters().ExecuteDeleteAsync();
    foreach (var c in configs)
        db.OAuthProviderConfigs.Add(new OAuthProviderConfigEntity
        {
            UserId = Guid.Parse(c["userId"]!), ProviderKey = c["provider"]!,
            ClientIdCipher = cipher.EncryptString(c["clientId"]!), ClientSecretCipher = cipher.EncryptString(c["clientSecret"]!),
            ScopesJson = c["scopesJson"], RedirectUri = c["redirectUri"],
        });
    foreach (var t in tokens)
        db.OAuthTokens.Add(new OAuthTokenEntity
        {
            UserId = Guid.Parse(t["userId"]!), ProviderKey = t["provider"]!, Account = t["account"] ?? "",
            AccessTokenCipher = cipher.EncryptString(t["accessToken"]!),
            RefreshTokenCipher = t["refreshToken"] is { } rt ? cipher.EncryptString(rt) : [],
            ScopesJson = t["scopesJson"], ExpiresAt = t["expiresAt"] is { } e ? DateTimeOffset.Parse(e) : null,
        });
    await db.SaveChangesAsync();
    Console.WriteLine($"Imported {configs.Count} configs and {tokens.Count} tokens into the vault.");
}
