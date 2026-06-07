using System.Text;

namespace DonkeyWork.Vault.Core.Crypto;

/// <summary>
/// Envelope encryption for secret-at-rest columns. Each call generates a fresh per-row DEK,
/// AES-256-GCM-encrypts the payload, wraps the DEK with the active KEK, and emits a
/// self-describing blob (carries its kekId) so rotation and provider swaps need no migration.
/// </summary>
public interface IEnvelopeCipher
{
    /// <summary>Encrypts plaintext into a self-describing envelope blob.</summary>
    byte[] Encrypt(ReadOnlySpan<byte> plaintext);

    /// <summary>Decrypts an envelope blob produced by <see cref="Encrypt"/>.</summary>
    byte[] Decrypt(ReadOnlySpan<byte> blob);

    /// <summary>UTF-8 convenience wrapper over <see cref="Encrypt"/>.</summary>
    byte[] EncryptString(string plaintext) => Encrypt(Encoding.UTF8.GetBytes(plaintext));

    /// <summary>UTF-8 convenience wrapper over <see cref="Decrypt"/>.</summary>
    string DecryptToString(ReadOnlySpan<byte> blob) => Encoding.UTF8.GetString(Decrypt(blob));
}
