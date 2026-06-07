namespace DonkeyWork.Vault.Persistence;

public sealed class VaultPersistenceOptions
{
    public const string SectionName = "Vault:Persistence";

    public string ConnectionString { get; set; } = string.Empty;
}
