using FirewallDetector.Core.Infrastructure;
using FirewallDetector.Core.Models;
using FirewallDetector.Core.Network;

namespace FirewallDetector.Core.Local;

public enum HostPlatform { Windows, Linux, Other }

/// <summary>Runs every firewall provider that applies to this machine and merges the result.</summary>
public sealed class LocalAuditor
{
    private readonly IReadOnlyList<IFirewallProvider> _providers;
    private readonly string _platformName;

    public LocalAuditor(IReadOnlyList<IFirewallProvider> providers, string platformName)
    {
        _providers = providers;
        _platformName = platformName;
    }

    public static LocalAuditor ForCurrentHost(ICommandRunner? runner = null)
    {
        runner ??= new ProcessCommandRunner();
        var platform = CurrentPlatform();
        return new LocalAuditor(ProvidersFor(platform, runner), platform.ToString().ToLowerInvariant());
    }

    public static HostPlatform CurrentPlatform() =>
        OperatingSystem.IsWindows() ? HostPlatform.Windows
        : OperatingSystem.IsLinux() ? HostPlatform.Linux
        : HostPlatform.Other;

    public static IReadOnlyList<IFirewallProvider> ProvidersFor(HostPlatform platform, ICommandRunner runner) => platform switch
    {
        HostPlatform.Windows => [new WindowsFirewallProvider(runner)],
        HostPlatform.Linux =>
        [
            new UfwProvider(runner),
            new FirewalldProvider(runner),
            new NftablesProvider(runner),
            new IptablesProvider(runner),
        ],
        _ => [],
    };

    public async Task<LocalAuditResult> AuditAsync(CancellationToken ct = default)
    {
        var tasks = _providers.Select(p => p.InspectAsync(ct)).ToArray();
        var backends = (await Task.WhenAll(tasks).ConfigureAwait(false)).SelectMany(b => b).ToList();

        bool? active = backends.Any(b => b.State == BackendState.Active)
            ? true
            : backends.Any(b => b.State == BackendState.Unknown) || backends.Count == 0
                ? null
                : false;

        return new LocalAuditResult
        {
            Platform = _platformName,
            Backends = backends,
            FirewallActive = active,
            Elevated = Environment.IsPrivilegedProcess,
        };
    }
}

/// <summary>Turns raw firewall state into findings.</summary>
public static class LocalAuditAnalyzer
{
    private const string Module = "local";

    public static IReadOnlyList<Finding> Analyze(LocalAuditResult audit)
    {
        var findings = new List<Finding>();
        var installed = audit.Backends.Where(b => b.State != BackendState.NotInstalled).ToList();

        if (audit.FirewallActive == false)
        {
            findings.Add(new Finding
            {
                Id = "LOCAL-001",
                Module = Module,
                Severity = Severity.Critical,
                Title = "No active host firewall",
                Detail = installed.Count == 0
                    ? "No supported firewall is installed on this machine."
                    : "Installed firewall(s) are not enforcing any policy: " + string.Join(", ", installed.Select(b => b.Name)) + ".",
                Remediation = "Enable a host firewall with a default-deny inbound policy.",
            });
        }
        else if (audit.FirewallActive is null)
        {
            findings.Add(new Finding
            {
                Id = "LOCAL-006",
                Module = Module,
                Severity = Severity.Low,
                Title = "Firewall state could not be determined",
                Detail = installed.Count == 0
                    ? "This platform has no supported firewall provider."
                    : "Firewall tooling is present but could not be read: "
                        + string.Join("; ", installed.Where(b => b.Error is not null).Select(b => $"{b.Name}: {b.Error}")),
                Remediation = "Re-run with administrator/root privileges.",
            });
        }

        foreach (var backend in installed)
        {
            AnalyzeProfiles(backend, findings);
            AnalyzeRules(backend, findings);
        }

        var managers = installed
            .Where(b => b.State == BackendState.Active && b.Name is "ufw" or "firewalld")
            .Select(b => b.Name)
            .ToList();
        if (managers.Count > 1)
        {
            findings.Add(new Finding
            {
                Id = "LOCAL-007",
                Module = Module,
                Severity = Severity.Medium,
                Title = "Multiple firewall managers are active",
                Detail = string.Join(" and ", managers) + " are both active and can overwrite each other's rules.",
                Remediation = "Standardise on one firewall manager and disable the other.",
            });
        }

        return findings;
    }

    private static void AnalyzeProfiles(FirewallBackend backend, List<Finding> findings)
    {
        var isWindows = backend.Name == "windows-defender-firewall";

        foreach (var profile in backend.Profiles)
        {
            if (isWindows && !profile.Enabled)
            {
                var isPublic = profile.Name.Equals("Public", StringComparison.OrdinalIgnoreCase);
                findings.Add(new Finding
                {
                    Id = "LOCAL-002",
                    Module = Module,
                    Severity = isPublic ? Severity.Critical : Severity.High,
                    Title = $"Firewall profile '{profile.Name}' is disabled",
                    Detail = $"The {profile.Name} profile of Windows Defender Firewall is turned off, so no inbound filtering applies on networks of that type.",
                    Remediation = $"Set-NetFirewallProfile -Profile {profile.Name} -Enabled True",
                    Evidence = new Dictionary<string, string> { ["backend"] = backend.Name, ["profile"] = profile.Name },
                });
                continue;
            }

            if (profile.Enabled && profile.DefaultInbound == "allow" && backend.State == BackendState.Active)
            {
                findings.Add(new Finding
                {
                    Id = "LOCAL-003",
                    Module = Module,
                    Severity = Severity.High,
                    Title = $"Default inbound policy is allow ({backend.Name}: {profile.Name})",
                    Detail = "Inbound traffic that matches no rule is accepted. A firewall should deny by default and allow by exception.",
                    Remediation = "Change the default inbound policy to block/drop and add explicit allow rules.",
                    Evidence = new Dictionary<string, string> { ["backend"] = backend.Name, ["profile"] = profile.Name },
                });
            }
        }
    }

    private static void AnalyzeRules(FirewallBackend backend, List<Finding> findings)
    {
        foreach (var rule in backend.Rules)
        {
            if (!rule.Enabled || rule.Action != RuleAction.Allow || rule.Direction != RuleDirection.Inbound)
            {
                continue;
            }

            if (!PortCatalog.IsAny(rule.RemoteAddresses))
            {
                continue;
            }

            var evidence = new Dictionary<string, string>
            {
                ["backend"] = backend.Name,
                ["rule"] = rule.Name,
                ["ports"] = rule.LocalPorts,
                ["protocol"] = rule.Protocol,
                ["remote"] = rule.RemoteAddresses,
            };
            if (rule.Profile is not null)
            {
                evidence["profile"] = rule.Profile;
            }

            // Rules scoped to Domain/Private networks only are less exposed than ones that apply on Public.
            var trustedOnly = IsTrustedProfileOnly(rule.Profile);

            if (PortCatalog.IsAny(rule.LocalPorts))
            {
                // Application-scoped "any port" rules are how Windows apps normally register; only flag unscoped ones.
                if (rule.Program is null && IsAnyProtocolOrTransport(rule.Protocol))
                {
                    findings.Add(new Finding
                    {
                        Id = "LOCAL-005",
                        Module = Module,
                        Severity = trustedOnly ? Severity.Medium : Severity.High,
                        Title = "Rule allows all inbound ports from any address",
                        Detail = $"'{rule.Name}' accepts inbound traffic on every port from any source, which largely bypasses the firewall.",
                        Remediation = "Restrict the rule to the specific ports and source ranges that are needed, or remove it.",
                        Evidence = evidence,
                    });
                }

                continue;
            }

            var exposed = PortCatalog.Sensitive
                .Where(kv => PortCatalog.RuleCovers(rule.LocalPorts, kv.Key))
                .OrderByDescending(kv => kv.Value)
                .ToList();
            if (exposed.Count == 0)
            {
                continue;
            }

            var severity = exposed[0].Value;
            if (trustedOnly && severity > Severity.Low)
            {
                severity -= 1;
            }

            var names = string.Join(", ", exposed.Select(kv => $"{kv.Key}/{PortCatalog.ServiceName(kv.Key)}"));
            findings.Add(new Finding
            {
                Id = "LOCAL-004",
                Module = Module,
                Severity = severity,
                Title = $"Sensitive service open to any address ({names})",
                Detail = $"'{rule.Name}' allows inbound {names} from any source address.",
                Remediation = "Limit the rule to trusted source ranges (management network, VPN) or remove it.",
                Evidence = evidence,
            });
        }
    }

    private static bool IsTrustedProfileOnly(string? profile)
    {
        if (string.IsNullOrWhiteSpace(profile))
        {
            return false;
        }

        var parts = profile.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts.Length > 0 && parts.All(p =>
            p.Equals("Domain", StringComparison.OrdinalIgnoreCase) || p.Equals("Private", StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsAnyProtocolOrTransport(string protocol) =>
        PortCatalog.IsAny(protocol)
        || protocol.Equals("tcp", StringComparison.OrdinalIgnoreCase)
        || protocol.Equals("udp", StringComparison.OrdinalIgnoreCase)
        || protocol == "6"
        || protocol == "17";
}
