namespace FirewallDetector.Core.Models;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// <summary>A single observation the platform wants an operator to see.</summary>
public sealed record Finding
{
    public required string Id { get; init; }
    public required string Module { get; init; }
    public required Severity Severity { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public string? Target { get; init; }
    public string? Remediation { get; init; }
    public IReadOnlyDictionary<string, string> Evidence { get; init; } = new Dictionary<string, string>();
}

// ---------- Local audit ----------

public enum RuleDirection { Inbound, Outbound, Forward }

public enum RuleAction { Allow, Block }

public enum BackendState
{
    /// <summary>The backend is installed and enforcing a policy.</summary>
    Active,
    /// <summary>The backend is installed but not enforcing anything.</summary>
    Inactive,
    NotInstalled,
    /// <summary>Present, but its state could not be read (usually missing privileges).</summary>
    Unknown,
}

public sealed record FirewallRule
{
    public required string Name { get; init; }
    public required string Source { get; init; }
    public RuleDirection Direction { get; init; } = RuleDirection.Inbound;
    public RuleAction Action { get; init; } = RuleAction.Allow;
    public bool Enabled { get; init; } = true;
    public string Protocol { get; init; } = "any";
    public string LocalPorts { get; init; } = "any";
    public string RemoteAddresses { get; init; } = "any";
    public string? Profile { get; init; }
    public string? Program { get; init; }
}

public sealed record FirewallProfile
{
    public required string Name { get; init; }
    public bool Enabled { get; init; }
    /// <summary>"allow", "block" or "unknown".</summary>
    public string DefaultInbound { get; init; } = "unknown";
    public string DefaultOutbound { get; init; } = "unknown";
}

public sealed record FirewallBackend
{
    public required string Name { get; init; }
    public required BackendState State { get; init; }
    public string? Detail { get; init; }
    public string? Error { get; init; }
    public IReadOnlyList<FirewallProfile> Profiles { get; init; } = [];
    public IReadOnlyList<FirewallRule> Rules { get; init; } = [];
}

public sealed record LocalAuditResult
{
    public required string Platform { get; init; }
    public required IReadOnlyList<FirewallBackend> Backends { get; init; }
    /// <summary>True/false when known, null when nothing could be inspected.</summary>
    public bool? FirewallActive { get; init; }
    public bool Elevated { get; init; }
}

// ---------- Network probe ----------

public enum PortState { Open, Closed, Filtered }

public enum FilteringVerdict
{
    NoFilteringObserved,
    FilteringDetected,
    DefaultDropLikely,
    UnreachableOrFullyFiltered,
    Inconclusive,
}

public sealed record PortResult
{
    public required int Port { get; init; }
    public required PortState State { get; init; }
    public required string Reason { get; init; }
    public double LatencyMs { get; init; }
    public string? Service { get; init; }
}

public sealed record HostProbeResult
{
    public required string Target { get; init; }
    public string? ResolvedAddress { get; init; }
    public IReadOnlyList<PortResult> Ports { get; init; } = [];
    public int Open { get; init; }
    public int Closed { get; init; }
    public int Filtered { get; init; }
    public FilteringVerdict Verdict { get; init; } = FilteringVerdict.Inconclusive;
    public string Explanation { get; init; } = "";
    public string? Error { get; init; }
}

// ---------- WAF ----------

public sealed record WafMatch
{
    public required string Name { get; init; }
    public required string Vendor { get; init; }
    public required string Kind { get; init; }
    public required int Confidence { get; init; }
    public IReadOnlyList<string> Evidence { get; init; } = [];
}

public sealed record WafResult
{
    public required string Url { get; init; }
    public bool Reachable { get; init; }
    public bool ActiveProbe { get; init; }
    public int? BaselineStatus { get; init; }
    public int? ProvocationStatus { get; init; }
    public bool Detected { get; init; }
    public bool GenericBlockingObserved { get; init; }
    public IReadOnlyList<WafMatch> Matches { get; init; } = [];
    public string? Notes { get; init; }
    public string? Error { get; init; }
}

// ---------- Report ----------

public sealed record ScanReport
{
    public string SchemaVersion { get; init; } = "1.0";
    public string Tool { get; init; } = "wallscope";
    public required string ToolVersion { get; init; }
    public required string Host { get; init; }
    public required string Os { get; init; }
    public required DateTimeOffset StartedUtc { get; init; }
    public required DateTimeOffset FinishedUtc { get; init; }
    public LocalAuditResult? LocalAudit { get; init; }
    public IReadOnlyList<HostProbeResult> NetworkProbes { get; init; } = [];
    public IReadOnlyList<WafResult> WafResults { get; init; } = [];
    public IReadOnlyList<Finding> Findings { get; init; } = [];
}
