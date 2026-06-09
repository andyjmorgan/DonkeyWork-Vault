using DonkeyWork.Vault.Core.Audit;

namespace DonkeyWork.Vault.Core.Tests.Audit;

public class AuditHeaderRedactorTests
{
    [Theory]
    [InlineData("authorization")]
    [InlineData("Authorization")]
    [InlineData("AUTHORIZATION")]
    [InlineData("x-api-key")]
    [InlineData("X-Api-Key")]
    [InlineData("x-internal-token")]
    [InlineData("cookie")]
    [InlineData("set-cookie")]
    [InlineData("proxy-authorization")]
    public void Redact_ExplicitDenyHeaders_AreMasked(string name)
    {
        Assert.Equal(AuditHeaderRedactor.Redacted, AuditHeaderRedactor.Redact(name, "super-secret-value"));
    }

    [Theory]
    [InlineData("x-refresh-token")]   // *token*
    [InlineData("session-token")]     // *token*
    [InlineData("client-secret")]     // *secret*
    [InlineData("x-user-password")]   // *password*
    [InlineData("signing-key")]       // *-key
    [InlineData("api-key")]           // *-key
    [InlineData("grpc-token")]        // grpc-* must NOT bypass the deny patterns
    [InlineData("grpc-secret")]       // grpc-* must NOT bypass the deny patterns
    [InlineData("grpc-api-key")]      // grpc-* must NOT bypass the deny patterns
    public void Redact_PatternDenyHeaders_AreMasked(string name)
    {
        Assert.True(AuditHeaderRedactor.IsDenied(name), $"expected {name} to be denied");
        Assert.Equal(AuditHeaderRedactor.Redacted, AuditHeaderRedactor.Redact(name, "leak"));
    }

    [Theory]
    [InlineData("user-agent", "donkeywork-cli/1.0")]
    [InlineData("content-type", "application/grpc")]
    [InlineData("accept", "application/json")]
    [InlineData("x-request-id", "abc-123")]
    [InlineData("traceparent", "00-trace-span-01")]
    [InlineData("x-forwarded-for", "1.2.3.4")]
    [InlineData("x-real-ip", "1.2.3.4")]
    [InlineData("host", "vault.internal")]
    public void Redact_AllowlistedHeaders_AreVerbatim(string name, string value)
    {
        Assert.Equal(value, AuditHeaderRedactor.Redact(name, value));
    }

    [Fact]
    public void Redact_GrpcFramingHeaders_AreMaskedByDefault()
    {
        // grpc-* framing headers aren't useful in an audit row; deny-by-default masks them,
        // and there is no grpc-aware allowlisting (gRPC is being removed).
        Assert.Equal(AuditHeaderRedactor.Redacted, AuditHeaderRedactor.Redact("grpc-encoding", "gzip"));
        Assert.Equal(AuditHeaderRedactor.Redacted, AuditHeaderRedactor.Redact("grpc-timeout", "100m"));
    }

    [Fact]
    public void Redact_UnknownHeader_IsMaskedByDefault()
    {
        // Deny-by-default: anything not allowlisted is masked even if it looks innocuous.
        Assert.Equal(AuditHeaderRedactor.Redacted, AuditHeaderRedactor.Redact("x-custom-thing", "value"));
    }

    [Fact]
    public void Redact_Collection_AuthorizationAndApiKeyNeverSurviveVerbatim()
    {
        var headers = new[]
        {
            new KeyValuePair<string, string>("Authorization", "Bearer dwv_topsecret"),
            new KeyValuePair<string, string>("X-Api-Key", "dwv_anotherSecret"),
            new KeyValuePair<string, string>("x-internal-token", "internal-hop-secret"),
            new KeyValuePair<string, string>("User-Agent", "agent/1.0"),
            new KeyValuePair<string, string>("traceparent", "00-aaa-bbb-01"),
        };

        var result = AuditHeaderRedactor.Redact(headers);

        // Keys are lower-cased, secrets masked, allowlisted kept.
        Assert.Equal(AuditHeaderRedactor.Redacted, result["authorization"]);
        Assert.Equal(AuditHeaderRedactor.Redacted, result["x-api-key"]);
        Assert.Equal(AuditHeaderRedactor.Redacted, result["x-internal-token"]);
        Assert.Equal("agent/1.0", result["user-agent"]);
        Assert.Equal("00-aaa-bbb-01", result["traceparent"]);

        // No secret value appears anywhere in the redacted map.
        var serialized = string.Join("|", result.Values);
        Assert.DoesNotContain("dwv_topsecret", serialized);
        Assert.DoesNotContain("dwv_anotherSecret", serialized);
        Assert.DoesNotContain("internal-hop-secret", serialized);
    }

    [Fact]
    public void Redact_Collection_IsCaseInsensitiveOnKeys()
    {
        var headers = new[]
        {
            new KeyValuePair<string, string>("AUTHORIZATION", "Bearer x"),
            new KeyValuePair<string, string>("authorization", "Bearer y"),
        };
        var result = AuditHeaderRedactor.Redact(headers);
        Assert.Single(result);
        Assert.Equal(AuditHeaderRedactor.Redacted, result["authorization"]);
    }
}
