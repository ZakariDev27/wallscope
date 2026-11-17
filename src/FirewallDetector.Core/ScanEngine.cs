using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FirewallDetector.Core.Local;
using FirewallDetector.Core.Models;
using FirewallDetector.Core.Network;
using FirewallDetector.Core.Waf;

namespace FirewallDetector.Core;

public sealed record ScanOptions
{
    public bool LocalAudit { get; init; }
    public IReadOnlyList<string> Targets { get; init; } = [];
    public IReadOnlyList<int> Ports { get; init; } = PortCatalog.Top;
    public IReadOnlyList<string> Urls { get; init; } = [];
    public ProbeOptions Probe { get; init; } = new();
    public WafOptions Waf { get; init; } = new();
}

/// <summary>Runs the requested modules and assembles one report.</summary>
public sealed class ScanEngine
{
    private readonly LocalAuditor _auditor;
    private readonly PortProber _prober;
    private readonly WafDetector _waf;

    public ScanEngine(LocalAuditor? auditor = null, PortProber? prober = null, WafDetector? waf = null)
    {
        _auditor = auditor ?? LocalAuditor.ForCurrentHost();
        _prober = prober ?? new PortProber();
        _waf = waf ?? new WafDetector();
    }

    public static string Version =>
        Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";

    public async Task<ScanReport> RunAsync(ScanOptions options, CancellationToken ct = default)
    {
        var started = DateTimeOffset.UtcNow;
        var findings = new List<Finding>();

        LocalAuditResult? audit = null;
        if (options.LocalAudit)
        {
            audit = await _auditor.AuditAsync(ct).ConfigureAwait(false);
            findings.AddRange(LocalAuditAnalyzer.Analyze(audit));
        }

        var probes = new List<HostProbeResult>();
        foreach (var target in options.Targets)
        {
            var probe = await _prober.ProbeAsync(target, options.Ports, options.Probe, ct).ConfigureAwait(false);
            probes.Add(probe);
            findings.AddRange(FilteringAnalyzer.Analyze(probe));
        }

        var wafResults = new List<WafResult>();
        foreach (var url in options.Urls)
        {
            var result = await _waf.DetectAsync(url, options.Waf, ct).ConfigureAwait(false);
            wafResults.Add(result);
            findings.AddRange(WafDetector.Analyze(result));
        }

        return new ScanReport
        {
            ToolVersion = Version,
            Host = Environment.MachineName,
            Os = RuntimeInformation.OSDescription,
            StartedUtc = started,
            FinishedUtc = DateTimeOffset.UtcNow,
            LocalAudit = audit,
            NetworkProbes = probes,
            WafResults = wafResults,
            Findings = [.. findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Id, StringComparer.Ordinal)],
        };
    }
}

/// <summary>
/// Remote modules only run against other people's machines when the operator says they may.
/// Loopback and this machine's own name never need the acknowledgement.
/// </summary>
public static class TargetPolicy
{
    public static bool IsLocal(string hostOrUrl)
    {
        var host = hostOrUrl;
        if (Uri.TryCreate(hostOrUrl, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
        {
            host = uri.Host;
        }

        host = host.Trim('[', ']');
        if (host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
            || host.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)
            || host.Equals(Environment.MachineName, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address);
    }

    public static IReadOnlyList<string> RemoteTargets(IEnumerable<string> targets) =>
        [.. targets.Where(t => !IsLocal(t))];
}

public static class ReportSerializer
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public static string ToJson(ScanReport report) => JsonSerializer.Serialize(report, Options);

    public static ScanReport FromJson(string json) =>
        JsonSerializer.Deserialize<ScanReport>(json, Options) ?? throw new JsonException("Report is empty.");

    public static string ToText(ScanReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"WallScope {report.ToolVersion}  |  {report.Host}  |  {report.Os}");
        sb.AppendLine(new string('-', 72));

        if (report.LocalAudit is { } audit)
        {
            var state = audit.FirewallActive switch { true => "ACTIVE", false => "NOT ACTIVE", _ => "UNKNOWN" };
            sb.AppendLine($"Local firewall: {state}{(audit.Elevated ? "" : "  (not elevated; some details may be hidden)")}");
            foreach (var backend in audit.Backends.Where(b => b.State != BackendState.NotInstalled))
            {
                sb.AppendLine($"  {backend.Name,-28} {backend.State,-9} {backend.Detail ?? backend.Error}");
                foreach (var profile in backend.Profiles)
                {
                    sb.AppendLine($"    profile {profile.Name,-24} {(profile.Enabled ? "on " : "off")} inbound={profile.DefaultInbound} outbound={profile.DefaultOutbound}");
                }
            }

            sb.AppendLine();
        }

        foreach (var probe in report.NetworkProbes)
        {
            sb.AppendLine($"Network probe: {probe.Target} ({probe.ResolvedAddress ?? "unresolved"})  ->  {probe.Verdict}");
            sb.AppendLine($"  open={probe.Open} closed={probe.Closed} filtered={probe.Filtered}");
            foreach (var port in probe.Ports.Where(p => p.State == PortState.Open))
            {
                sb.AppendLine($"    {port.Port,5}/tcp open  {port.Service}");
            }

            sb.AppendLine($"  {probe.Explanation}");
            sb.AppendLine();
        }

        foreach (var waf in report.WafResults)
        {
            var summary = waf.Error is not null ? "error: " + waf.Error
                : waf.Matches.Count > 0 ? string.Join(", ", waf.Matches.Select(m => $"{m.Name} ({m.Confidence}%)"))
                : waf.GenericBlockingObserved ? "unidentified WAF behaviour"
                : "none detected";
            sb.AppendLine($"WAF check: {waf.Url}  ->  {summary}");
        }

        if (report.WafResults.Count > 0)
        {
            sb.AppendLine();
        }

        sb.AppendLine($"Findings ({report.Findings.Count})");
        foreach (var finding in report.Findings)
        {
            sb.AppendLine($"  [{finding.Severity.ToString().ToUpperInvariant(),-8}] {finding.Id}  {finding.Title}{(finding.Target is null ? "" : "  <" + finding.Target + ">")}");
        }

        return sb.ToString();
    }
}
