using System.Text.Json;
using System.Text.RegularExpressions;
using FirewallDetector.Core.Infrastructure;
using FirewallDetector.Core.Models;

namespace FirewallDetector.Core.Local;

/// <summary>Inspects one firewall technology on the local machine.</summary>
public interface IFirewallProvider
{
    string Name { get; }

    Task<IReadOnlyList<FirewallBackend>> InspectAsync(CancellationToken ct = default);
}

internal static class ProviderHelpers
{
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(20);

    public static FirewallBackend NotInstalled(string name) =>
        new() { Name = name, State = BackendState.NotInstalled };

    public static FirewallBackend Unreadable(string name, CommandResult result) => new()
    {
        Name = name,
        State = BackendState.Unknown,
        Error = result.TimedOut
            ? "Command timed out."
            : result.LooksLikePermissionDenied
                ? "Insufficient privileges to read the ruleset. Re-run as root/administrator."
                : FirstLine(result.StdErr, result.StdOut),
    };

    private static string FirstLine(params string[] texts)
    {
        foreach (var text in texts)
        {
            var line = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault();
            if (!string.IsNullOrEmpty(line))
            {
                return line;
            }
        }

        return "Command failed without output.";
    }
}

/// <summary>nftables, read through <c>nft -j list ruleset</c>.</summary>
public sealed class NftablesProvider(ICommandRunner runner) : IFirewallProvider
{
    public string Name => "nftables";

    public async Task<IReadOnlyList<FirewallBackend>> InspectAsync(CancellationToken ct = default)
    {
        var result = await runner.RunAsync("nft", ["-j", "list", "ruleset"], ProviderHelpers.Timeout, ct).ConfigureAwait(false);
        if (!result.Started)
        {
            return [ProviderHelpers.NotInstalled(Name)];
        }

        if (!result.Success)
        {
            return [ProviderHelpers.Unreadable(Name, result)];
        }

        try
        {
            return [Parse(result.StdOut)];
        }
        catch (JsonException ex)
        {
            return [new FirewallBackend { Name = Name, State = BackendState.Unknown, Error = "Could not parse nft output: " + ex.Message }];
        }
    }

    public static FirewallBackend Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return new FirewallBackend { Name = "nftables", State = BackendState.Inactive, Detail = "Ruleset is empty." };
        }

        using var doc = JsonDocument.Parse(json);
        var profiles = new List<FirewallProfile>();
        var rules = new List<FirewallRule>();
        var inputChains = new HashSet<string>(StringComparer.Ordinal);
        var totalRules = 0;

        if (!doc.RootElement.TryGetProperty("nftables", out var entries) || entries.ValueKind != JsonValueKind.Array)
        {
            return new FirewallBackend { Name = "nftables", State = BackendState.Inactive, Detail = "Ruleset is empty." };
        }

        foreach (var entry in entries.EnumerateArray())
        {
            if (!entry.TryGetProperty("chain", out var chain))
            {
                continue;
            }

            var hook = GetString(chain, "hook");
            if (hook != "input")
            {
                continue;
            }

            var key = ChainKey(chain, "name");
            inputChains.Add(key);
            var policy = GetString(chain, "policy") ?? "accept";
            profiles.Add(new FirewallProfile
            {
                Name = key,
                Enabled = true,
                DefaultInbound = policy == "accept" ? "allow" : "block",
            });
        }

        foreach (var entry in entries.EnumerateArray())
        {
            if (!entry.TryGetProperty("rule", out var rule))
            {
                continue;
            }

            totalRules++;
            var key = ChainKey(rule, "chain");
            if (!inputChains.Contains(key) || !rule.TryGetProperty("expr", out var expr) || expr.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            var parsed = ParseRule(expr, key, rules.Count + 1);
            if (parsed is not null)
            {
                rules.Add(parsed);
            }
        }

        var enforcing = profiles.Any(p => p.DefaultInbound == "block") || (profiles.Count > 0 && totalRules > 0);
        return new FirewallBackend
        {
            Name = "nftables",
            State = enforcing ? BackendState.Active : BackendState.Inactive,
            Detail = $"{profiles.Count} input chain(s), {totalRules} rule(s) in total. Rules reached through jumps to other chains are not expanded.",
            Profiles = profiles,
            Rules = rules,
        };
    }

    private static FirewallRule? ParseRule(JsonElement expr, string chainKey, int index)
    {
        RuleAction? action = null;
        var ports = "any";
        var sources = "any";
        var protocol = "any";
        var conditional = false;

        foreach (var statement in expr.EnumerateArray())
        {
            if (statement.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            if (statement.TryGetProperty("accept", out _))
            {
                action = RuleAction.Allow;
            }
            else if (statement.TryGetProperty("drop", out _) || statement.TryGetProperty("reject", out _))
            {
                action = RuleAction.Block;
            }
            else if (statement.TryGetProperty("match", out var match))
            {
                var field = match.TryGetProperty("left", out var left)
                    && left.ValueKind == JsonValueKind.Object
                    && left.TryGetProperty("payload", out var payload)
                        ? GetString(payload, "field")
                        : null;

                if (field == "dport" && match.TryGetProperty("right", out var portValue))
                {
                    ports = Flatten(portValue);
                    protocol = GetString(left.GetProperty("payload"), "protocol") ?? protocol;
                }
                else if (field == "saddr" && match.TryGetProperty("right", out var sourceValue))
                {
                    sources = Flatten(sourceValue);
                }
                else if (!IsProtocolSelector(match))
                {
                    // Interface, conntrack state, destination address... the rule is narrower than it looks.
                    conditional = true;
                }
            }
        }

        // An accept that depends on conditions we do not model must not be reported as a broad allow.
        if (action == RuleAction.Allow && conditional)
        {
            return null;
        }

        if (action is null)
        {
            return null;
        }

        return new FirewallRule
        {
            Name = $"{chainKey} rule {index}",
            Source = "nftables",
            Action = action.Value,
            Protocol = protocol,
            LocalPorts = ports,
            RemoteAddresses = sources,
        };
    }

    private static bool IsProtocolSelector(JsonElement match) =>
        match.TryGetProperty("left", out var left)
        && left.ValueKind == JsonValueKind.Object
        && left.TryGetProperty("meta", out var meta)
        && GetString(meta, "key") is "l4proto" or "nfproto";

    /// <summary>Turns an nft JSON value (number, string, set, range, prefix) into a compact string.</summary>
    private static string Flatten(JsonElement value)
    {
        switch (value.ValueKind)
        {
            case JsonValueKind.Number:
                return value.GetRawText();
            case JsonValueKind.String:
                return value.GetString() ?? "any";
            case JsonValueKind.Array:
                return string.Join(",", value.EnumerateArray().Select(Flatten));
            case JsonValueKind.Object:
                if (value.TryGetProperty("set", out var set))
                {
                    return Flatten(set);
                }

                if (value.TryGetProperty("range", out var range) && range.ValueKind == JsonValueKind.Array && range.GetArrayLength() == 2)
                {
                    return Flatten(range[0]) + "-" + Flatten(range[1]);
                }

                if (value.TryGetProperty("prefix", out var prefix))
                {
                    return $"{GetString(prefix, "addr")}/{(prefix.TryGetProperty("len", out var len) ? len.GetRawText() : "?")}";
                }

                return value.GetRawText();
            default:
                return "any";
        }
    }

    private static string ChainKey(JsonElement element, string nameProperty) =>
        $"{GetString(element, "family")} {GetString(element, "table")}/{GetString(element, nameProperty)}";

    private static string? GetString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}

/// <summary>Legacy iptables, read through <c>iptables -S</c>.</summary>
public sealed partial class IptablesProvider(ICommandRunner runner) : IFirewallProvider
{
    private static readonly HashSet<string> ConditionalOptions = new(StringComparer.Ordinal)
    {
        "-i", "--in-interface", "-d", "--destination", "--sport", "--sports", "--ctstate", "--state", "--icmp-type",
    };

    public string Name => "iptables";

    public async Task<IReadOnlyList<FirewallBackend>> InspectAsync(CancellationToken ct = default)
    {
        var result = await runner.RunAsync("iptables", ["-S"], ProviderHelpers.Timeout, ct).ConfigureAwait(false);
        if (!result.Started)
        {
            return [ProviderHelpers.NotInstalled(Name)];
        }

        return result.Success ? [Parse(result.StdOut)] : [ProviderHelpers.Unreadable(Name, result)];
    }

    public static FirewallBackend Parse(string output)
    {
        var profiles = new List<FirewallProfile>();
        var rules = new List<FirewallRule>();
        var appended = 0;

        foreach (var raw in output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var tokens = raw.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length >= 3 && tokens[0] == "-P")
            {
                if (tokens[1] == "INPUT")
                {
                    profiles.Add(new FirewallProfile
                    {
                        Name = "INPUT",
                        Enabled = true,
                        DefaultInbound = tokens[2] == "ACCEPT" ? "allow" : "block",
                    });
                }

                continue;
            }

            if (tokens.Length < 2 || tokens[0] != "-A")
            {
                continue;
            }

            appended++;
            if (tokens[1] != "INPUT")
            {
                continue;
            }

            var target = Option(tokens, "-j");
            RuleAction? action = target switch
            {
                "ACCEPT" => RuleAction.Allow,
                "DROP" or "REJECT" => RuleAction.Block,
                _ => null,
            };
            if (action is null)
            {
                continue;
            }

            // Accepts tied to an interface, connection state, etc. are narrower than "allow from anywhere".
            if (action == RuleAction.Allow && tokens.Any(t => ConditionalOptions.Contains(t)))
            {
                continue;
            }

            rules.Add(new FirewallRule
            {
                Name = raw,
                Source = "iptables",
                Action = action.Value,
                Protocol = Option(tokens, "-p") ?? "any",
                LocalPorts = (Option(tokens, "--dport") ?? Option(tokens, "--dports") ?? "any").Replace(':', '-'),
                RemoteAddresses = Option(tokens, "-s") ?? "any",
            });
        }

        var enforcing = profiles.Any(p => p.DefaultInbound == "block") || appended > 0;
        return new FirewallBackend
        {
            Name = "iptables",
            State = enforcing ? BackendState.Active : BackendState.Inactive,
            Detail = $"{appended} rule(s) in the filter table (IPv4). Rules reached through jumps to other chains are not expanded.",
            Profiles = profiles,
            Rules = rules,
        };
    }

    private static string? Option(string[] tokens, string name)
    {
        var index = Array.IndexOf(tokens, name);
        return index >= 0 && index + 1 < tokens.Length ? tokens[index + 1] : null;
    }
}

/// <summary>Uncomplicated Firewall. Falls back to /etc/ufw/ufw.conf when not running as root.</summary>
public sealed partial class UfwProvider(ICommandRunner runner, Func<string, string?>? readFile = null) : IFirewallProvider
{
    private readonly Func<string, string?> _readFile = readFile ?? DefaultReadFile;

    public string Name => "ufw";

    public async Task<IReadOnlyList<FirewallBackend>> InspectAsync(CancellationToken ct = default)
    {
        var result = await runner.RunAsync("ufw", ["status", "verbose"], ProviderHelpers.Timeout, ct).ConfigureAwait(false);
        if (!result.Started)
        {
            return [ProviderHelpers.NotInstalled(Name)];
        }

        if (result.Success)
        {
            return [Parse(result.StdOut)];
        }

        // Unprivileged: the config file still says whether ufw is switched on.
        var config = _readFile("/etc/ufw/ufw.conf");
        if (config is not null)
        {
            var enabled = EnabledRegex().IsMatch(config);
            return
            [
                new FirewallBackend
                {
                    Name = Name,
                    State = enabled ? BackendState.Active : BackendState.Inactive,
                    Detail = "State read from /etc/ufw/ufw.conf; rules need root to inspect.",
                    Error = result.LooksLikePermissionDenied ? "Insufficient privileges to list rules." : null,
                },
            ];
        }

        return [ProviderHelpers.Unreadable(Name, result)];
    }

    public static FirewallBackend Parse(string output)
    {
        var lines = output.Split('\n').Select(l => l.TrimEnd('\r')).ToArray();
        var active = lines.Any(l => l.Trim().Equals("Status: active", StringComparison.OrdinalIgnoreCase));
        var profiles = new List<FirewallProfile>();
        var rules = new List<FirewallRule>();

        foreach (var line in lines)
        {
            var defaults = DefaultsRegex().Match(line);
            if (defaults.Success)
            {
                profiles.Add(new FirewallProfile
                {
                    Name = "default",
                    Enabled = active,
                    DefaultInbound = defaults.Groups["in"].Value == "allow" ? "allow" : "block",
                    DefaultOutbound = defaults.Groups["out"].Value == "allow" ? "allow" : "block",
                });
                continue;
            }

            var rule = RuleRegex().Match(line);
            if (!rule.Success)
            {
                continue;
            }

            var direction = rule.Groups["dir"].Value;
            var to = V6Suffix().Replace(rule.Groups["to"].Value, "").Trim();
            var from = V6Suffix().Replace(rule.Groups["from"].Value, "").Trim();
            var slash = to.LastIndexOf('/');
            var protocol = slash > 0 ? to[(slash + 1)..] : "any";
            var ports = slash > 0 ? to[..slash] : to;

            rules.Add(new FirewallRule
            {
                Name = line.Trim(),
                Source = "ufw",
                Direction = direction == "OUT" ? RuleDirection.Outbound : direction == "FWD" ? RuleDirection.Forward : RuleDirection.Inbound,
                Action = rule.Groups["action"].Value is "ALLOW" or "LIMIT" ? RuleAction.Allow : RuleAction.Block,
                Protocol = protocol,
                LocalPorts = ports.Equals("Anywhere", StringComparison.OrdinalIgnoreCase) ? "any" : ports.Replace(':', '-'),
                RemoteAddresses = from.Equals("Anywhere", StringComparison.OrdinalIgnoreCase) ? "any" : from,
            });
        }

        return new FirewallBackend
        {
            Name = "ufw",
            State = active ? BackendState.Active : BackendState.Inactive,
            Detail = active ? $"{rules.Count} rule(s)." : "ufw is installed but inactive.",
            Profiles = profiles,
            Rules = active ? rules : [],
        };
    }

    private static string? DefaultReadFile(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    [GeneratedRegex(@"^\s*ENABLED\s*=\s*yes\s*$", RegexOptions.IgnoreCase | RegexOptions.Multiline)]
    private static partial Regex EnabledRegex();

    [GeneratedRegex(@"^Default:\s*(?<in>\w+)\s*\(incoming\),\s*(?<out>\w+)\s*\(outgoing\)", RegexOptions.IgnoreCase)]
    private static partial Regex DefaultsRegex();

    [GeneratedRegex(@"^(?<to>\S.*?)\s{2,}(?<action>ALLOW|DENY|REJECT|LIMIT)(?:\s+(?<dir>IN|OUT|FWD))?\s{2,}(?<from>\S.*?)\s*$")]
    private static partial Regex RuleRegex();

    [GeneratedRegex(@"\s*\(v6\)")]
    private static partial Regex V6Suffix();
}

/// <summary>firewalld, read through <c>firewall-cmd</c>.</summary>
public sealed class FirewalldProvider(ICommandRunner runner) : IFirewallProvider
{
    private static readonly Dictionary<string, string> ServicePorts = new(StringComparer.OrdinalIgnoreCase)
    {
        ["ssh"] = "22", ["http"] = "80", ["https"] = "443", ["ftp"] = "21", ["telnet"] = "23",
        ["samba"] = "445", ["mysql"] = "3306", ["postgresql"] = "5432", ["rdp"] = "3389",
        ["vnc-server"] = "5900-5903", ["redis"] = "6379", ["mongodb"] = "27017", ["smtp"] = "25",
        ["dns"] = "53", ["cockpit"] = "9090",
    };

    public string Name => "firewalld";

    public async Task<IReadOnlyList<FirewallBackend>> InspectAsync(CancellationToken ct = default)
    {
        var state = await runner.RunAsync("firewall-cmd", ["--state"], ProviderHelpers.Timeout, ct).ConfigureAwait(false);
        if (!state.Started)
        {
            return [ProviderHelpers.NotInstalled(Name)];
        }

        var text = (state.StdOut + state.StdErr).Trim().ToLowerInvariant();
        if (text.Contains("not running"))
        {
            return [new FirewallBackend { Name = Name, State = BackendState.Inactive, Detail = "firewalld is installed but not running." }];
        }

        if (!state.Success)
        {
            return [ProviderHelpers.Unreadable(Name, state)];
        }

        var list = await runner.RunAsync("firewall-cmd", ["--list-all"], ProviderHelpers.Timeout, ct).ConfigureAwait(false);
        if (!list.Success)
        {
            return
            [
                new FirewallBackend
                {
                    Name = Name,
                    State = BackendState.Active,
                    Detail = "firewalld is running; the active zone could not be listed.",
                    Error = ProviderHelpers.Unreadable(Name, list).Error,
                },
            ];
        }

        return [ParseListAll(list.StdOut)];
    }

    public static FirewallBackend ParseListAll(string output)
    {
        var lines = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.TrimEnd('\r')).ToArray();
        var zone = lines.FirstOrDefault(l => l.Length > 0 && !char.IsWhiteSpace(l[0]))?.Trim() ?? "default";
        var rules = new List<FirewallRule>();
        var target = "default";

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            var colon = trimmed.IndexOf(':');
            if (colon <= 0)
            {
                continue;
            }

            var key = trimmed[..colon];
            var values = trimmed[(colon + 1)..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            switch (key)
            {
                case "target":
                    target = values.FirstOrDefault() ?? "default";
                    break;
                case "services":
                    foreach (var service in values)
                    {
                        rules.Add(new FirewallRule
                        {
                            Name = "service: " + service,
                            Source = "firewalld",
                            Profile = zone,
                            LocalPorts = ServicePorts.GetValueOrDefault(service, service),
                        });
                    }

                    break;
                case "ports":
                    foreach (var port in values)
                    {
                        var slash = port.IndexOf('/');
                        rules.Add(new FirewallRule
                        {
                            Name = "port: " + port,
                            Source = "firewalld",
                            Profile = zone,
                            Protocol = slash > 0 ? port[(slash + 1)..] : "any",
                            LocalPorts = slash > 0 ? port[..slash] : port,
                        });
                    }

                    break;
            }
        }

        return new FirewallBackend
        {
            Name = "firewalld",
            State = BackendState.Active,
            Detail = $"Zone {zone}; {rules.Count} allowed service(s)/port(s).",
            Profiles =
            [
                new FirewallProfile
                {
                    Name = zone,
                    Enabled = true,
                    DefaultInbound = target.Equals("ACCEPT", StringComparison.OrdinalIgnoreCase) ? "allow" : "block",
                    DefaultOutbound = "allow",
                },
            ],
            Rules = rules,
        };
    }
}
