namespace DonkeyWork.Vault.Core.Crypto;

/// <summary>
/// Configuration for the envelope cipher's local KEK provider.
/// Bound from the "Vault:Crypto" configuration section.
/// </summary>
public sealed class VaultCryptoOptions
{
    public const string SectionName = "Vault:Crypto";

    /// <summary>
    /// The KEK id used to wrap new DEKs. Must be a key present in <see cref="Keks"/>.
    /// Rotating = add a new key here and to <see cref="Keks"/>; old ciphertext keeps
    /// its embedded kekId and still decrypts against the historical key.
    /// </summary>
    public string ActiveKekId { get; set; } = string.Empty;

    /// <summary>
    /// Map of kekId -> base64-encoded 256-bit (32 byte) key material.
    /// All historical keys must remain here so old rows can be decrypted.
    /// </summary>
    public Dictionary<string, string> Keks { get; set; } = new();
}
