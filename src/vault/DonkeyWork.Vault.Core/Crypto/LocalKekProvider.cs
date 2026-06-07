using System.Security.Cryptography;
using Microsoft.Extensions.Options;

namespace DonkeyWork.Vault.Core.Crypto;

/// <summary>
/// Default KEK provider for dev and small self-host deployments. Reads KEK material from
/// configuration (<see cref="VaultCryptoOptions"/>) and AES-256-GCM-wraps DEKs.
/// A wrapped DEK is laid out as: nonce(12) || tag(16) || ciphertext(dek length).
/// </summary>
public sealed class LocalKekProvider : IKekProvider
{
    private const int NonceSize = 12;
    private const int TagSize = 16;

    private readonly IReadOnlyDictionary<string, byte[]> _keks;

    public string ActiveKekId { get; }

    public LocalKekProvider(IOptions<VaultCryptoOptions> options)
    {
        var o = options.Value;

        if (string.IsNullOrWhiteSpace(o.ActiveKekId))
        {
            throw new InvalidOperationException("Vault:Crypto:ActiveKekId is not configured.");
        }

        if (o.Keks.Count == 0)
        {
            throw new InvalidOperationException("Vault:Crypto:Keks is empty; at least one KEK is required.");
        }

        var keks = new Dictionary<string, byte[]>(o.Keks.Count, StringComparer.Ordinal);
        foreach (var (id, base64) in o.Keks)
        {
            byte[] key;
            try
            {
                key = Convert.FromBase64String(base64);
            }
            catch (FormatException ex)
            {
                throw new InvalidOperationException($"KEK '{id}' is not valid base64.", ex);
            }

            if (key.Length != 32)
            {
                throw new InvalidOperationException($"KEK '{id}' must be 32 bytes (256-bit); got {key.Length}.");
            }

            keks[id] = key;
        }

        if (!keks.ContainsKey(o.ActiveKekId))
        {
            throw new InvalidOperationException($"ActiveKekId '{o.ActiveKekId}' is not present in Vault:Crypto:Keks.");
        }

        _keks = keks;
        ActiveKekId = o.ActiveKekId;
    }

    public byte[] Wrap(ReadOnlySpan<byte> dek)
    {
        var kek = _keks[ActiveKekId];

        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[dek.Length];
        var tag = new byte[TagSize];

        using var gcm = new AesGcm(kek, TagSize);
        gcm.Encrypt(nonce, dek, ciphertext, tag);

        var wrapped = new byte[NonceSize + TagSize + ciphertext.Length];
        nonce.CopyTo(wrapped.AsSpan(0, NonceSize));
        tag.CopyTo(wrapped.AsSpan(NonceSize, TagSize));
        ciphertext.CopyTo(wrapped.AsSpan(NonceSize + TagSize));
        return wrapped;
    }

    public byte[] Unwrap(string kekId, ReadOnlySpan<byte> wrappedDek)
    {
        if (!_keks.TryGetValue(kekId, out var kek))
        {
            throw new CryptographicException($"Unknown kekId '{kekId}'; no matching key in configuration.");
        }

        if (wrappedDek.Length < NonceSize + TagSize)
        {
            throw new CryptographicException("Wrapped DEK is too short.");
        }

        var nonce = wrappedDek.Slice(0, NonceSize);
        var tag = wrappedDek.Slice(NonceSize, TagSize);
        var ciphertext = wrappedDek.Slice(NonceSize + TagSize);

        var dek = new byte[ciphertext.Length];
        using var gcm = new AesGcm(kek, TagSize);
        gcm.Decrypt(nonce, ciphertext, tag, dek);
        return dek;
    }
}
