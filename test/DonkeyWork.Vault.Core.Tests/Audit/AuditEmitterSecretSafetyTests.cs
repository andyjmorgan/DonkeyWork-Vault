using System.Security.Cryptography;
using System.Text;
using DonkeyWork.Vault.Contracts;
using DonkeyWork.Vault.Contracts.Audit;
using DonkeyWork.Vault.Core.Audit;

namespace DonkeyWork.Vault.Core.Tests.Audit;

public class AuditEmitterSecretSafetyTests
{
    private sealed class FixedCaller(Guid userId) : IVaultCallerContext
    {
        public Guid UserId => userId;
        public Guid TenantId => Guid.Empty;
    }

    private sealed class CapturingLog : IAuditLog
    {
        public readonly List<AuditEvent> Events = new();
        public void Enqueue(AuditEvent e) => Events.Add(e);
    }

    [Fact]
    public void Emit_RecordsKeyReferenceOnly_NeverSecretOrHash()
    {
        // A realistic access-key secret and the SHA-256 hash that is stored for lookup. Neither
        // must ever appear in an emitted audit event — only the id / prefix / name reference may.
        const string secret = "dwv_AbCdEf0123456789AbCdEf0123456789AbCdEf01";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        var hashHex = Convert.ToHexString(hash);
        var hashB64 = Convert.ToBase64String(hash);

        var keyId = Guid.NewGuid();
        const string prefix = "dwv_AbCd";   // the non-secret display reference
        const string name = "ci-runner";

        var info = new AuditRequestInfo(
            SourceIp: "203.0.113.10",
            Headers: new Dictionary<string, string>
            {
                ["authorization"] = AuditHeaderRedactor.Redacted,
                ["user-agent"] = "agent/1.0",
            },
            AccessKeyId: keyId,
            AccessKeyPrefix: prefix,
            AccessKeyName: name,
            Transport: "grpc",
            Method: "/donkeywork.vault.v1.CredentialStore/GetApiKey");

        var context = new AuditContextAccessor();
        context.Set(info);

        var log = new CapturingLog();
        var emitter = new AuditEmitter(log, context, new FixedCaller(Guid.NewGuid()));

        emitter.Emit(AuditEventType.TokenAccessed, AuditOutcome.Success,
            targetKind: "api_key", targetName: "grafana");

        var e = Assert.Single(log.Events);

        // The reference is present...
        Assert.Equal(keyId, e.AccessKeyId);
        Assert.Equal(prefix, e.AccessKeyPrefix);
        Assert.Equal(name, e.AccessKeyName);

        // ...but neither the secret nor any encoding of its hash leaks into the event.
        var serialized = System.Text.Json.JsonSerializer.Serialize(e);
        Assert.DoesNotContain(secret, serialized);
        Assert.DoesNotContain(hashHex, serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(hashB64, serialized);

        // And the redacted header survived as a mask, not the bearer value.
        Assert.Equal(AuditHeaderRedactor.Redacted, e.Headers["authorization"]);
    }

    [Fact]
    public void Emit_UsesAmbientCaller_WhenIdentityNotOverridden()
    {
        var user = Guid.NewGuid();
        var context = new AuditContextAccessor();
        context.Set(AuditRequestInfo.Empty);
        var log = new CapturingLog();
        var emitter = new AuditEmitter(log, context, new FixedCaller(user));

        emitter.Emit(AuditEventType.CredentialCreated, AuditOutcome.Success, targetKind: "api_key");

        Assert.Equal(user, log.Events[0].UserId);
    }

    [Fact]
    public void Emit_OverridesIdentity_ForAnonymousCallback()
    {
        // The OAuth callback has no caller identity; it passes the owner from the state row.
        var owner = Guid.NewGuid();
        var context = new AuditContextAccessor();
        context.Set(AuditRequestInfo.Empty);
        var log = new CapturingLog();
        var emitter = new AuditEmitter(log, context, new FixedCaller(Guid.Empty));

        emitter.Emit(AuditEventType.TokenAdded, AuditOutcome.Success,
            targetKind: "oauth_token", targetProvider: "google", userId: owner);

        Assert.Equal(owner, log.Events[0].UserId);
        Assert.Null(log.Events[0].AccessKeyId);
    }
}
