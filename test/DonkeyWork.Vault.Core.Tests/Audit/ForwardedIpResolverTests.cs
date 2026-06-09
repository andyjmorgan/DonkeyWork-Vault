using System.Net;
using DonkeyWork.Vault.Core.Audit;

namespace DonkeyWork.Vault.Core.Tests.Audit;

public class ForwardedIpResolverTests
{
    private static readonly string[] LabTrusted = { "10.42.0.0/16", "192.168.0.0/16" };

    [Fact]
    public void Resolve_TrustedPeer_HonoursLeftmostXForwardedFor()
    {
        var resolver = ForwardedIpResolver.FromCidrs(LabTrusted);
        var peer = IPAddress.Parse("10.42.0.7"); // ingress pod — trusted

        var ip = resolver.Resolve(peer, "203.0.113.9, 10.42.0.7", xRealIp: null);

        Assert.Equal("203.0.113.9", ip);
    }

    [Fact]
    public void Resolve_TrustedPeer_FallsBackToXRealIp_WhenNoXff()
    {
        var resolver = ForwardedIpResolver.FromCidrs(LabTrusted);
        var peer = IPAddress.Parse("192.168.69.1");

        var ip = resolver.Resolve(peer, xForwardedFor: null, xRealIp: "198.51.100.4");

        Assert.Equal("198.51.100.4", ip);
    }

    [Fact]
    public void Resolve_UntrustedPeer_IgnoresForwardedHeaders_UsesSocketPeer()
    {
        var resolver = ForwardedIpResolver.FromCidrs(LabTrusted);
        var peer = IPAddress.Parse("8.8.8.8"); // direct, untrusted client

        // A malicious client spoofs XFF; it must NOT be honoured.
        var ip = resolver.Resolve(peer, "1.2.3.4", xRealIp: "5.6.7.8");

        Assert.Equal("8.8.8.8", ip);
    }

    [Fact]
    public void Resolve_NoTrustedRanges_NeverHonoursForwarded()
    {
        var resolver = ForwardedIpResolver.FromCidrs(Array.Empty<string>());
        var peer = IPAddress.Parse("10.42.0.7");

        var ip = resolver.Resolve(peer, "203.0.113.9", xRealIp: null);

        Assert.Equal("10.42.0.7", ip);
    }

    [Fact]
    public void Resolve_StripsPortFromForwardedValue()
    {
        var resolver = ForwardedIpResolver.FromCidrs(LabTrusted);
        var peer = IPAddress.Parse("10.42.1.1");

        var ip = resolver.Resolve(peer, "203.0.113.9:54321", xRealIp: null);

        Assert.Equal("203.0.113.9", ip);
    }

    [Fact]
    public void Resolve_NullPeer_ReturnsNull()
    {
        var resolver = ForwardedIpResolver.FromCidrs(LabTrusted);
        Assert.Null(resolver.Resolve(null, "203.0.113.9", "1.1.1.1"));
    }

    [Fact]
    public void TrustedNetwork_Contains_RespectsPrefixBoundary()
    {
        var net = TrustedNetwork.TryParse("192.168.69.0/24")!;
        Assert.True(net.Contains(IPAddress.Parse("192.168.69.27")));
        Assert.False(net.Contains(IPAddress.Parse("192.168.70.1")));
    }

    [Fact]
    public void TrustedNetwork_TryParse_BareAddressIsSingleHost()
    {
        var net = TrustedNetwork.TryParse("127.0.0.1")!;
        Assert.Equal(32, net.PrefixLength);
        Assert.True(net.Contains(IPAddress.Parse("127.0.0.1")));
        Assert.False(net.Contains(IPAddress.Parse("127.0.0.2")));
    }

    [Theory]
    [InlineData("not-a-cidr")]
    [InlineData("10.0.0.0/99")]
    [InlineData("")]
    public void TrustedNetwork_TryParse_RejectsMalformed(string cidr)
    {
        Assert.Null(TrustedNetwork.TryParse(cidr));
    }
}
