using System.Net;
using System.Net.Sockets;

namespace DonkeyWork.Vault.Core.Audit;

/// <summary>A trusted network range, parsed from CIDR (e.g. <c>10.42.0.0/16</c>).</summary>
public sealed record TrustedNetwork(IPAddress Prefix, int PrefixLength)
{
    /// <summary>Parse a CIDR string; returns null if malformed.</summary>
    public static TrustedNetwork? TryParse(string cidr)
    {
        if (string.IsNullOrWhiteSpace(cidr))
        {
            return null;
        }
        var slash = cidr.IndexOf('/');
        if (slash < 0)
        {
            // A bare address is treated as a /32 (or /128) single host.
            return IPAddress.TryParse(cidr.Trim(), out var single)
                ? new TrustedNetwork(single, single.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32)
                : null;
        }
        var addrPart = cidr[..slash].Trim();
        var lenPart = cidr[(slash + 1)..].Trim();
        if (!IPAddress.TryParse(addrPart, out var prefix) || !int.TryParse(lenPart, out var len))
        {
            return null;
        }
        var max = prefix.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32;
        if (len < 0 || len > max)
        {
            return null;
        }
        return new TrustedNetwork(prefix, len);
    }

    /// <summary>True if <paramref name="address"/> falls within this network.</summary>
    public bool Contains(IPAddress address)
    {
        if (address.AddressFamily != Prefix.AddressFamily)
        {
            // Compare IPv4-mapped IPv6 against IPv4 networks by unwrapping.
            if (address.IsIPv4MappedToIPv6 && Prefix.AddressFamily == AddressFamily.InterNetwork)
            {
                address = address.MapToIPv4();
            }
            else
            {
                return false;
            }
        }

        var addrBytes = address.GetAddressBytes();
        var prefixBytes = Prefix.GetAddressBytes();
        if (addrBytes.Length != prefixBytes.Length)
        {
            return false;
        }

        var fullBytes = PrefixLength / 8;
        var remainingBits = PrefixLength % 8;
        for (var i = 0; i < fullBytes; i++)
        {
            if (addrBytes[i] != prefixBytes[i])
            {
                return false;
            }
        }
        if (remainingBits == 0)
        {
            return true;
        }
        var mask = (byte)(0xFF << (8 - remainingBits));
        return (addrBytes[fullBytes] & mask) == (prefixBytes[fullBytes] & mask);
    }
}

/// <summary>
/// Resolves the real client IP behind ingress using a trusted-proxy policy: forwarded headers
/// (<c>X-Forwarded-For</c> left-most untrusted hop, then <c>X-Real-IP</c>) are honoured only when
/// the immediate socket peer is within the configured trusted ranges; otherwise the socket peer
/// is used. This mirrors what ASP.NET <c>ForwardedHeadersMiddleware</c> does centrally, and is
/// factored out so the trusted-proxy decision is unit-testable without the HTTP pipeline.
/// </summary>
public sealed class ForwardedIpResolver(IReadOnlyList<TrustedNetwork> trustedProxies)
{
    private readonly IReadOnlyList<TrustedNetwork> _trusted = trustedProxies;

    public static ForwardedIpResolver FromCidrs(IEnumerable<string> cidrs)
    {
        var nets = cidrs
            .Select(TrustedNetwork.TryParse)
            .Where(n => n is not null)
            .Select(n => n!)
            .ToList();
        return new ForwardedIpResolver(nets);
    }

    public bool IsTrusted(IPAddress? peer) =>
        peer is not null && _trusted.Any(n => n.Contains(peer));

    /// <summary>
    /// Resolve the client IP. <paramref name="peer"/> is the socket peer; the header lookups are
    /// honoured only when the peer is trusted. Returns the resolved address as a string, or null
    /// if nothing usable is available.
    /// </summary>
    public string? Resolve(IPAddress? peer, string? xForwardedFor, string? xRealIp)
    {
        // Only honour forwarded headers from a trusted immediate peer; otherwise a client could
        // spoof X-Forwarded-For to forge the source IP in the audit trail.
        if (IsTrusted(peer))
        {
            // X-Forwarded-For is "client, proxy1, proxy2"; the left-most is the original client.
            if (!string.IsNullOrWhiteSpace(xForwardedFor))
            {
                foreach (var hop in xForwardedFor.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var candidate = StripPort(hop);
                    if (IPAddress.TryParse(candidate, out var parsed))
                    {
                        return Normalize(parsed);
                    }
                }
            }
            if (!string.IsNullOrWhiteSpace(xRealIp) && IPAddress.TryParse(StripPort(xRealIp.Trim()), out var real))
            {
                return Normalize(real);
            }
        }

        return peer is null ? null : Normalize(peer);
    }

    private static string Normalize(IPAddress address) =>
        (address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address).ToString();

    private static string StripPort(string value)
    {
        // IPv6 in brackets: [::1]:1234 -> ::1
        if (value.StartsWith('[') )
        {
            var close = value.IndexOf(']');
            return close > 0 ? value[1..close] : value;
        }
        // IPv4 with a port: 1.2.3.4:5678 -> 1.2.3.4 (a bare IPv6 has many colons, leave it).
        var colon = value.IndexOf(':');
        if (colon > 0 && value.IndexOf(':', colon + 1) < 0)
        {
            return value[..colon];
        }
        return value;
    }
}
