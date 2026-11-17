using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using FirewallDetector.Core.Models;

namespace FirewallDetector.Core.Network;

public sealed record ConnectOutcome(PortState State, string Reason, double LatencyMs);

/// <summary>One TCP connection attempt. Abstracted so the classifier can be tested without a network.</summary>
public interface ITcpConnector
{
    Task<ConnectOutcome> ConnectAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken ct = default);
}

/// <summary>
/// Full TCP handshake using the operating system's socket API. No raw sockets, so no special
/// privileges are needed. How the attempt fails tells us what is in the path:
/// SYN-ACK = open, RST = closed, silence or ICMP unreachable = filtered.
/// </summary>
public sealed class SocketTcpConnector : ITcpConnector
{
    private static readonly TimeSpan WindowsMinimumTimeout = TimeSpan.FromMilliseconds(3000);

    public async Task<ConnectOutcome> ConnectAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken ct = default)
    {
        // Windows re-sends the SYN after a reset, so a closed port takes 1-2 seconds to report as refused.
        // A shorter wait would misread every closed port as filtered.
        if (OperatingSystem.IsWindows() && timeout < WindowsMinimumTimeout)
        {
            timeout = WindowsMinimumTimeout;
        }

        using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(timeout);
        var stopwatch = Stopwatch.StartNew();

        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), timeoutCts.Token).ConfigureAwait(false);
            return new ConnectOutcome(PortState.Open, "syn-ack", stopwatch.Elapsed.TotalMilliseconds);
        }
        catch (OperationCanceledException)
        {
            ct.ThrowIfCancellationRequested();
            return new ConnectOutcome(PortState.Filtered, "no-response", stopwatch.Elapsed.TotalMilliseconds);
        }
        catch (SocketException ex)
        {
            var elapsed = stopwatch.Elapsed.TotalMilliseconds;
            return ex.SocketErrorCode switch
            {
                SocketError.ConnectionRefused => new ConnectOutcome(PortState.Closed, "rst", elapsed),
                SocketError.TimedOut => new ConnectOutcome(PortState.Filtered, "no-response", elapsed),
                SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.HostDown
                    => new ConnectOutcome(PortState.Filtered, "icmp-unreachable", elapsed),
                SocketError.AccessDenied => new ConnectOutcome(PortState.Filtered, "blocked-locally", elapsed),
                _ => new ConnectOutcome(PortState.Filtered, "error-" + ex.SocketErrorCode.ToString().ToLowerInvariant(), elapsed),
            };
        }
    }
}

public sealed record ProbeOptions
{
    public TimeSpan Timeout { get; init; } = TimeSpan.FromMilliseconds(1500);
    public int Concurrency { get; init; } = 32;
    /// <summary>Extra attempts for ports that did not answer, to separate packet loss from filtering.</summary>
    public int Retries { get; init; } = 1;
}

public sealed class PortProber
{
    private readonly ITcpConnector _connector;
    private readonly Func<string, CancellationToken, Task<IPAddress[]>> _resolve;

    public PortProber(ITcpConnector? connector = null, Func<string, CancellationToken, Task<IPAddress[]>>? resolver = null)
    {
        _connector = connector ?? new SocketTcpConnector();
        _resolve = resolver ?? Dns.GetHostAddressesAsync;
    }

    public async Task<HostProbeResult> ProbeAsync(string target, IReadOnlyList<int> ports, ProbeOptions? options = null, CancellationToken ct = default)
    {
        options ??= new ProbeOptions();

        IPAddress address;
        try
        {
            address = await ResolveAsync(target, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is SocketException or ArgumentException)
        {
            return new HostProbeResult
            {
                Target = target,
                Verdict = FilteringVerdict.Inconclusive,
                Explanation = "The target name could not be resolved.",
                Error = ex.Message,
            };
        }

        using var gate = new SemaphoreSlim(Math.Clamp(options.Concurrency, 1, 256));
        var tasks = ports.Select(port => ProbePortAsync(address, port, options, gate, ct)).ToArray();
        var results = (await Task.WhenAll(tasks).ConfigureAwait(false)).OrderBy(r => r.Port).ToList();

        var (verdict, explanation) = FilteringAnalyzer.Classify(results);
        return new HostProbeResult
        {
            Target = target,
            ResolvedAddress = address.ToString(),
            Ports = results,
            Open = results.Count(r => r.State == PortState.Open),
            Closed = results.Count(r => r.State == PortState.Closed),
            Filtered = results.Count(r => r.State == PortState.Filtered),
            Verdict = verdict,
            Explanation = explanation,
        };
    }

    private async Task<IPAddress> ResolveAsync(string target, CancellationToken ct)
    {
        if (IPAddress.TryParse(target, out var literal))
        {
            return literal;
        }

        var addresses = await _resolve(target, ct).ConfigureAwait(false);
        return addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
            ?? addresses.FirstOrDefault()
            ?? throw new ArgumentException($"'{target}' did not resolve to any address.");
    }

    private async Task<PortResult> ProbePortAsync(IPAddress address, int port, ProbeOptions options, SemaphoreSlim gate, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var outcome = await _connector.ConnectAsync(address, port, options.Timeout, ct).ConfigureAwait(false);
            for (var attempt = 0; attempt < options.Retries && outcome is { State: PortState.Filtered, Reason: "no-response" }; attempt++)
            {
                outcome = await _connector.ConnectAsync(address, port, options.Timeout, ct).ConfigureAwait(false);
            }

            return new PortResult
            {
                Port = port,
                State = outcome.State,
                Reason = outcome.Reason,
                LatencyMs = Math.Round(outcome.LatencyMs, 2),
                Service = PortCatalog.ServiceName(port),
            };
        }
        finally
        {
            gate.Release();
        }
    }
}

/// <summary>Infers whether a packet filter sits in front of a host from the mix of port states.</summary>
public static class FilteringAnalyzer
{
    private const string Module = "network";

    public static (FilteringVerdict Verdict, string Explanation) Classify(IReadOnlyList<PortResult> ports)
    {
        if (ports.Count == 0)
        {
            return (FilteringVerdict.Inconclusive, "No ports were probed.");
        }

        var open = ports.Count(p => p.State == PortState.Open);
        var closed = ports.Count(p => p.State == PortState.Closed);
        var filtered = ports.Count(p => p.State == PortState.Filtered);

        if (filtered == 0)
        {
            return (FilteringVerdict.NoFilteringObserved,
                $"Every probed port answered directly ({open} open, {closed} closed with RST). Nothing in the path dropped the probes.");
        }

        if (filtered == ports.Count)
        {
            return (FilteringVerdict.UnreachableOrFullyFiltered,
                "No probed port answered. The host is down, unroutable, or a firewall drops everything that was probed.");
        }

        if (closed > 0)
        {
            return (FilteringVerdict.FilteringDetected,
                $"The host's TCP stack answered some ports ({open} open, {closed} closed with RST) while {filtered} got no answer. "
                + "A stack that is reachable resets closed ports, so the silent ones are being dropped by a packet filter.");
        }

        return (FilteringVerdict.DefaultDropLikely,
            $"{open} port(s) are open and the other {filtered} got no answer at all. "
            + "That pattern matches a default-drop firewall that only lets through the published services.");
    }

    public static IReadOnlyList<Finding> Analyze(HostProbeResult result)
    {
        var findings = new List<Finding>();
        if (result.Error is not null)
        {
            findings.Add(new Finding
            {
                Id = "NET-005",
                Module = Module,
                Severity = Severity.Low,
                Target = result.Target,
                Title = "Target could not be probed",
                Detail = result.Error,
            });
            return findings;
        }

        var evidence = new Dictionary<string, string>
        {
            ["open"] = result.Open.ToString(),
            ["closed"] = result.Closed.ToString(),
            ["filtered"] = result.Filtered.ToString(),
            ["address"] = result.ResolvedAddress ?? "",
        };

        switch (result.Verdict)
        {
            case FilteringVerdict.FilteringDetected:
            case FilteringVerdict.DefaultDropLikely:
                findings.Add(new Finding
                {
                    Id = "NET-001",
                    Module = Module,
                    Severity = Severity.Info,
                    Target = result.Target,
                    Title = result.Verdict == FilteringVerdict.FilteringDetected ? "Firewall detected in the path" : "Default-drop firewall likely",
                    Detail = result.Explanation,
                    Evidence = evidence,
                });
                break;
            case FilteringVerdict.NoFilteringObserved:
                findings.Add(new Finding
                {
                    Id = "NET-002",
                    Module = Module,
                    Severity = Severity.Low,
                    Target = result.Target,
                    Title = "No packet filtering observed",
                    Detail = result.Explanation + " Either no firewall protects these ports from this vantage point, or it rejects with RST instead of dropping.",
                    Remediation = "Confirm a firewall with a default-deny policy sits between untrusted networks and this host.",
                    Evidence = evidence,
                });
                break;
            case FilteringVerdict.UnreachableOrFullyFiltered:
                findings.Add(new Finding
                {
                    Id = "NET-004",
                    Module = Module,
                    Severity = Severity.Info,
                    Target = result.Target,
                    Title = "Host unreachable or fully filtered",
                    Detail = result.Explanation,
                    Evidence = evidence,
                });
                break;
        }

        // Exposure only matters when probing across a network, not against loopback.
        var loopback = IPAddress.TryParse(result.ResolvedAddress, out var ip) && IPAddress.IsLoopback(ip);
        if (!loopback)
        {
            foreach (var port in result.Ports.Where(p => p.State == PortState.Open))
            {
                if (!PortCatalog.Sensitive.TryGetValue(port.Port, out var severity))
                {
                    continue;
                }

                findings.Add(new Finding
                {
                    Id = "NET-003",
                    Module = Module,
                    Severity = severity,
                    Target = result.Target,
                    Title = $"Sensitive service reachable: {port.Port}/{port.Service ?? "tcp"}",
                    Detail = $"Port {port.Port} ({port.Service ?? "unknown service"}) accepted a connection from this vantage point.",
                    Remediation = "Restrict this port to trusted source ranges at the firewall, or close it if it is not needed.",
                    Evidence = new Dictionary<string, string> { ["port"] = port.Port.ToString(), ["reason"] = port.Reason },
                });
            }
        }

        return findings;
    }
}
