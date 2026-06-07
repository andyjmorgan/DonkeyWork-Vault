using System.Security.Cryptography;
using System.Text;
using DonkeyWork.Vault.Core.Crypto;
using Microsoft.Extensions.Options;

namespace DonkeyWork.Vault.Core.Tests.Crypto;

public class EnvelopeCipherTests
{
    private static string Key(byte seed) => Convert.ToBase64String(Enumerable.Repeat(seed, 32).ToArray());

    private static IEnvelopeCipher Cipher(string active, params (string id, string b64)[] keks)
    {
        var opts = new VaultCryptoOptions
        {
            ActiveKekId = active,
            Keks = keks.ToDictionary(k => k.id, k => k.b64),
        };
        var kek = new LocalKekProvider(Options.Create(opts));
        return new EnvelopeCipherService(kek);
    }

    [Fact]
    public void RoundTrip_ReturnsOriginalPlaintext()
    {
        var cipher = Cipher("local:v1", ("local:v1", Key(1)));
        var secret = "sk-super-secret-grafana-token-éñ";

        var blob = cipher.EncryptString(secret);
        var recovered = cipher.DecryptToString(blob);

        Assert.Equal(secret, recovered);
    }

    [Fact]
    public void Encrypt_IsSelfDescribing_AndNotPlaintext()
    {
        var cipher = Cipher("local:v1", ("local:v1", Key(1)));
        var plaintext = Encoding.UTF8.GetBytes("plaintext-marker-value");

        var blob = cipher.Encrypt(plaintext);

        Assert.Equal((byte)'D', blob[0]);
        Assert.Equal((byte)'W', blob[1]);
        Assert.Equal((byte)'V', blob[2]);
        Assert.Equal((byte)'1', blob[3]);
        // The plaintext marker must not appear anywhere in the ciphertext blob.
        Assert.DoesNotContain("plaintext-marker-value", Encoding.UTF8.GetString(blob));
    }

    [Fact]
    public void Encrypt_TwoCalls_ProduceDifferentBlobs()
    {
        var cipher = Cipher("local:v1", ("local:v1", Key(1)));
        var a = cipher.EncryptString("same-input");
        var b = cipher.EncryptString("same-input");
        Assert.False(a.AsSpan().SequenceEqual(b)); // fresh DEK + nonce each time
    }

    [Fact]
    public void Rotation_DecryptsOldBlob_AfterActiveKeyChanges()
    {
        var v1 = ("local:v1", Key(1));
        var v2 = ("local:v2", Key(2));

        var before = Cipher("local:v1", v1, v2);
        var blob = before.EncryptString("written-under-v1");

        // Rotate: v2 becomes active, both keys still configured.
        var after = Cipher("local:v2", v1, v2);
        Assert.Equal("written-under-v1", after.DecryptToString(blob));
    }

    [Fact]
    public void Decrypt_TamperedCiphertext_Throws()
    {
        var cipher = Cipher("local:v1", ("local:v1", Key(1)));
        var blob = cipher.EncryptString("integrity-protected");

        blob[^1] ^= 0xFF; // flip a ciphertext byte

        Assert.ThrowsAny<CryptographicException>(() => { cipher.Decrypt(blob); });
    }

    [Fact]
    public void Decrypt_UnknownKek_Throws()
    {
        var written = Cipher("local:v1", ("local:v1", Key(1)));
        var blob = written.EncryptString("orphaned");

        // A provider that doesn't know local:v1 cannot unwrap.
        var other = Cipher("local:v9", ("local:v9", Key(9)));
        Assert.ThrowsAny<CryptographicException>(() => { other.Decrypt(blob); });
    }

    [Fact]
    public void Decrypt_BadMagic_Throws()
    {
        var cipher = Cipher("local:v1", ("local:v1", Key(1)));
        Assert.ThrowsAny<CryptographicException>(() => { cipher.Decrypt(new byte[] { 1, 2, 3, 4, 5 }); });
    }

    [Fact]
    public void LocalKekProvider_RejectsWrongKeyLength()
    {
        var opts = new VaultCryptoOptions
        {
            ActiveKekId = "local:v1",
            Keks = new() { ["local:v1"] = Convert.ToBase64String(new byte[16]) }, // 128-bit, too short
        };
        Assert.Throws<InvalidOperationException>(() => new LocalKekProvider(Options.Create(opts)));
    }
}
