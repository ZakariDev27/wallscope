using System.Text;
using System.Text.Json;
using FirewallDetector.Core.Infrastructure;
using FirewallDetector.Core.Models;

namespace FirewallDetector.Core.Local;

/// <summary>
/// Reads Windows Defender Firewall state through the NetSecurity PowerShell module,
/// plus any third-party firewall registered with Windows Security Center.
/// </summary>
public sealed class WindowsFirewallProvider : IFirewallProvider
{
    private const int MaxRules = 2000;

    // One round trip: profiles, enabled inbound allow rules, and registered third-party products.
    internal const string Script = """
        $ErrorActionPreference = 'Stop'
        $profiles = @(Get-NetFirewallProfile | ForEach-Object {
            [pscustomobject]@{
                Name = [string]$_.Name
                Enabled = [string]$_.Enabled
                DefaultInboundAction = [string]$_.DefaultInboundAction
                DefaultOutboundAction = [string]$_.DefaultOutboundAction
            }
        })
        $pf = @{}; Get-NetFirewallPortFilter -All | ForEach-Object { $pf[$_.InstanceID] = $_ }
        $af = @{}; Get-NetFirewallAddressFilter -All | ForEach-Object { $af[$_.InstanceID] = $_ }
        $pg = @{}; Get-NetFirewallApplicationFilter -All | ForEach-Object { $pg[$_.InstanceID] = $_ }
        $rules = @(Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow | ForEach-Object {
            [pscustomobject]@{
                Name = [string]$_.DisplayName
                Profile = [string]$_.Profile
                Protocol = [string]$pf[$_.Name].Protocol
                LocalPort = (@($pf[$_.Name].LocalPort) -join ',')
                RemoteAddress = (@($af[$_.Name].RemoteAddress) -join ',')
                Program = [string]$pg[$_.Name].Program
            }
        })
        $products = @()
        try {
            $products = @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName FirewallProduct -ErrorAction Stop |
                ForEach-Object { [pscustomobject]@{ Name = [string]$_.displayName; State = [string]$_.productState } })
        } catch { }
        [pscustomobject]@{ profiles = $profiles; rules = $rules; products = $products } | ConvertTo-Json -Depth 4 -Compress
        """;

    private readonly ICommandRunner _runner;

    public WindowsFirewallProvider(ICommandRunner runner) => _runner = runner;

    public string Name => "windows-defender-firewall";

    public async Task<IReadOnlyList<FirewallBackend>> InspectAsync(CancellationToken ct = default)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(Script));
        string[] args = ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded];

        var result = await _runner.RunAsync("powershell.exe", args, TimeSpan.FromSeconds(90), ct).ConfigureAwait(false);
        if (!result.Started)
        {
            result = await _runner.RunAsync("pwsh", args, TimeSpan.FromSeconds(90), ct).ConfigureAwait(false);
        }

        if (!result.Started)
        {
            return [new FirewallBackend { Name = Name, State = BackendState.Unknown, Error = "PowerShell was not found on this machine." }];
        }

        if (!result.Success)
        {
            var error = result.TimedOut ? "PowerShell timed out while reading firewall state." : FirstLine(result.StdErr);
            return [new FirewallBackend { Name = Name, State = BackendState.Unknown, Error = error }];
        }

        try
        {
            return Parse(result.StdOut);
        }
        catch (JsonException ex)
        {
            return [new FirewallBackend { Name = Name, State = BackendState.Unknown, Error = "Could not parse PowerShell output: " + ex.Message }];
        }
    }

    /// <summary>Parses the JSON document produced by <see cref="Script"/>.</summary>
    public static IReadOnlyList<FirewallBackend> Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        var profiles = new List<FirewallProfile>();
        foreach (var p in Items(root, "profiles"))
        {
            profiles.Add(new FirewallProfile
            {
                Name = Str(p, "Name") ?? "unknown",
                Enabled = IsTrue(Str(p, "Enabled")),
                // "NotConfigured" means the Windows built-in default applies: block inbound, allow outbound.
                DefaultInbound = MapAction(Str(p, "DefaultInboundAction"), whenNotConfigured: "block"),
                DefaultOutbound = MapAction(Str(p, "DefaultOutboundAction"), whenNotConfigured: "allow"),
            });
        }

        var rules = new List<FirewallRule>();
        foreach (var r in Items(root, "rules"))
        {
            if (rules.Count >= MaxRules)
            {
                break;
            }

            rules.Add(new FirewallRule
            {
                Name = Str(r, "Name") ?? "(unnamed rule)",
                Source = "windows-defender-firewall",
                Direction = RuleDirection.Inbound,
                Action = RuleAction.Allow,
                Protocol = Normalize(Str(r, "Protocol")),
                LocalPorts = Normalize(Str(r, "LocalPort")),
                RemoteAddresses = Normalize(Str(r, "RemoteAddress")),
                Profile = Str(r, "Profile"),
                Program = NullIfAny(Str(r, "Program")),
            });
        }

        var enabledCount = profiles.Count(p => p.Enabled);
        var state = profiles.Count == 0
            ? BackendState.Unknown
            : enabledCount > 0 ? BackendState.Active : BackendState.Inactive;

        var backends = new List<FirewallBackend>
        {
            new()
            {
                Name = "windows-defender-firewall",
                State = state,
                Detail = $"{enabledCount} of {profiles.Count} profiles enabled; {rules.Count} enabled inbound allow rules.",
                Profiles = profiles,
                Rules = rules,
            },
        };

        foreach (var product in Items(root, "products"))
        {
            var name = Str(product, "Name");
            if (string.IsNullOrWhiteSpace(name))
            {
                continue;
            }

            backends.Add(new FirewallBackend
            {
                Name = "third-party: " + name,
                State = IsSecurityCenterProductOn(Str(product, "State")) ? BackendState.Active : BackendState.Inactive,
                Detail = "Registered with Windows Security Center.",
            });
        }

        return backends;
    }

    /// <summary>
    /// Security Center packs product state into an integer; byte 1 (0x1000) is the "enabled" flag.
    /// </summary>
    public static bool IsSecurityCenterProductOn(string? productState) =>
        int.TryParse(productState, out var value) && (value & 0x1000) != 0;

    private static IEnumerable<JsonElement> Items(JsonElement root, string property)
    {
        if (!root.TryGetProperty(property, out var value))
        {
            yield break;
        }

        // Windows PowerShell 5.1 collapses single-element arrays into a bare object.
        if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.Object)
                {
                    yield return item;
                }
            }
        }
        else if (value.ValueKind == JsonValueKind.Object)
        {
            yield return value;
        }
    }

    private static string? Str(JsonElement element, string property)
    {
        if (!element.TryGetProperty(property, out var value))
        {
            return null;
        }

        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString(),
            JsonValueKind.Number => value.GetRawText(),
            JsonValueKind.True => "True",
            JsonValueKind.False => "False",
            _ => null,
        };
    }

    private static bool IsTrue(string? value) =>
        string.Equals(value, "True", StringComparison.OrdinalIgnoreCase) || value == "1";

    private static string MapAction(string? value, string whenNotConfigured) => value?.ToLowerInvariant() switch
    {
        "allow" => "allow",
        "block" => "block",
        "notconfigured" => whenNotConfigured,
        _ => "unknown",
    };

    private static string Normalize(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "any" : value.Trim();

    private static string? NullIfAny(string? value) =>
        string.IsNullOrWhiteSpace(value) || value.Equals("Any", StringComparison.OrdinalIgnoreCase) ? null : value;

    private static string FirstLine(string text)
    {
        var line = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
        return string.IsNullOrEmpty(line) ? "PowerShell returned an error." : line;
    }
}
