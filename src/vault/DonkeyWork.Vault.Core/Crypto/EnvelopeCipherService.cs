using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace DonkeyWork.Vault.Core.Crypto;

/// <summary>
/// AES-256-GCM envelope cipher with a per-row DEK wrapped by an <see cref="IKekProvider"/>.
///
/// On-disk blob layout (single byte[] / bytea column):
///   magic "DWV1" (4) | version (1) | kekIdLen (1) | kekId (utf8) |
///   wrappedDekLen (2, big-endian) | wrappedDek | nonce (12) | tag (16) | ciphertext
///
/// AAD is not used; integrity is provided by the GCM tag. The kekId travels in the header so
/// decryption routes to the correct (possibly historical) KEK without any schema change.
/// </summary>
public sealed class EnvelopeCipherService : IEnvelopeCipher
{
    private static readonly byte[] Magic = "DWV1"u8.ToArray();
    private const byte Version = 1;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int DekSize = 32;

    private readonly IKekProvider _kek;

    public EnvelopeCipherService(IKekProvider kek) => _kek = kek;

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        Span<byte> dek = stackalloc byte[DekSize];
        RandomNumberGenerator.Fill(dek);

        try
        {
            Span<byte> nonce = stackalloc byte[NonceSize];
            RandomNumberGenerator.Fill(nonce);

            var ciphertext = new byte[plaintext.Length];
            Span<byte> tag = stackalloc byte[TagSize];

            using (var gcm = new AesGcm(dek, TagSize))
            {
                gcm.Encrypt(nonce, plaintext, ciphertext, tag);
            }

            var wrappedDek = _kek.Wrap(dek);
            var kekIdBytes = Encoding.UTF8.GetBytes(_kek.ActiveKekId);

            if (kekIdBytes.Length > byte.MaxValue)
            {
                throw new InvalidOperationException("kekId is too long to encode (max 255 bytes).");
            }

            if (wrappedDek.Length > ushort.MaxValue)
            {
                throw new InvalidOperationException("wrapped DEK is too long to encode.");
            }

            var total = Magic.Length + 1 + 1 + kekIdBytes.Length + 2 + wrappedDek.Length
                        + NonceSize + TagSize + ciphertext.Length;
            var blob = new byte[total];
            var o = 0;

            Magic.CopyTo(blob.AsSpan(o)); o += Magic.Length;
            blob[o++] = Version;
            blob[o++] = (byte)kekIdBytes.Length;
            kekIdBytes.CopyTo(blob.AsSpan(o)); o += kekIdBytes.Length;
            BinaryPrimitives.WriteUInt16BigEndian(blob.AsSpan(o), (ushort)wrappedDek.Length); o += 2;
            wrappedDek.CopyTo(blob.AsSpan(o)); o += wrappedDek.Length;
            nonce.CopyTo(blob.AsSpan(o)); o += NonceSize;
            tag.CopyTo(blob.AsSpan(o)); o += TagSize;
            ciphertext.CopyTo(blob.AsSpan(o));

            return blob;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public byte[] Decrypt(ReadOnlySpan<byte> blob)
    {
        var o = 0;

        if (blob.Length < Magic.Length + 2 || !blob.Slice(0, Magic.Length).SequenceEqual(Magic))
        {
            throw new CryptographicException("Not a recognized envelope blob (bad magic).");
        }
        o += Magic.Length;

        var version = blob[o++];
        if (version != Version)
        {
            throw new CryptographicException($"Unsupported envelope version {version}.");
        }

        int kekIdLen = blob[o++];
        if (blob.Length < o + kekIdLen + 2)
        {
            throw new CryptographicException("Envelope truncated (kekId).");
        }

        var kekId = Encoding.UTF8.GetString(blob.Slice(o, kekIdLen)); o += kekIdLen;
        int wrappedLen = BinaryPrimitives.ReadUInt16BigEndian(blob.Slice(o)); o += 2;

        if (blob.Length < o + wrappedLen + NonceSize + TagSize)
        {
            throw new CryptographicException("Envelope truncated (body).");
        }

        var wrappedDek = blob.Slice(o, wrappedLen); o += wrappedLen;
        var nonce = blob.Slice(o, NonceSize); o += NonceSize;
        var tag = blob.Slice(o, TagSize); o += TagSize;
        var ciphertext = blob.Slice(o);

        var dek = _kek.Unwrap(kekId, wrappedDek);
        try
        {
            var plaintext = new byte[ciphertext.Length];
            using var gcm = new AesGcm(dek, TagSize);
            gcm.Decrypt(nonce, ciphertext, tag, plaintext);
            return plaintext;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }
}
