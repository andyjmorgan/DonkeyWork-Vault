namespace DonkeyWork.Vault.Core.Crypto;

/// <summary>
/// Wraps and unwraps per-row data encryption keys (DEKs) with a key-encryption key (KEK).
/// The <see cref="ActiveKekId"/> identifies the KEK used for new writes; the kekId is
/// embedded in each ciphertext header so unwraps route to the correct (possibly historical)
/// key — enabling append-only key rotation and pluggable backends (local, KMS, AKV, Transit).
/// </summary>
public interface IKekProvider
{
    /// <summary>Identifier of the KEK used to wrap new DEKs (e.g. "local:v1").</summary>
    string ActiveKekId { get; }

    /// <summary>Wraps a DEK with the active KEK. Returns the opaque wrapped blob.</summary>
    byte[] Wrap(ReadOnlySpan<byte> dek);

    /// <summary>Unwraps a previously wrapped DEK using the named KEK.</summary>
    byte[] Unwrap(string kekId, ReadOnlySpan<byte> wrappedDek);
}
