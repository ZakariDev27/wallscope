using FirewallDetector.Core.Models;

namespace FirewallDetector.Core.Network;

/// <summary>Port lists, service names and the services that should never face an untrusted network.</summary>
public static class PortCatalog
{
    public static readonly IReadOnlyList<int> Top =
    [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995,
        1433, 1521, 2375, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 8000, 8080, 8443, 9200, 11211, 27017,
    ];

    private static readonly Dictionary<int, string> Services = new()
    {
        [21] = "ftp", [22] = "ssh", [23] = "telnet", [25] = "smtp", [53] = "dns", [80] = "http",
        [110] = "pop3", [111] = "rpcbind", [135] = "msrpc", [139] = "netbios-ssn", [143] = "imap",
        [443] = "https", [445] = "smb", [465] = "smtps", [587] = "submission", [993] = "imaps",
        [995] = "pop3s", [1433] = "mssql", [1521] = "oracle", [2375] = "docker-api", [3306] = "mysql",
        [3389] = "rdp", [5432] = "postgresql", [5900] = "vnc", [5985] = "winrm-http", [5986] = "winrm-https",
        [6379] = "redis", [8000] = "http-alt", [8080] = "http-proxy", [8443] = "https-alt",
        [9200] = "elasticsearch", [11211] = "memcached", [27017] = "mongodb",
    };

    /// <summary>Services whose exposure to "any" source is worth a finding, with the severity to raise.</summary>
    public static readonly IReadOnlyDictionary<int, Severity> Sensitive = new Dictionary<int, Severity>
    {
        [21] = Severity.Medium,
        [22] = Severity.Medium,
        [23] = Severity.Critical,
        [135] = Severity.High,
        [139] = Severity.High,
        [445] = Severity.High,
        [1433] = Severity.High,
        [1521] = Severity.High,
        [2375] = Severity.Critical,
        [3306] = Severity.High,
        [3389] = Severity.High,
        [5432] = Severity.High,
        [5900] = Severity.High,
        [5985] = Severity.High,
        [5986] = Severity.High,
        [6379] = Severity.High,
        [9200] = Severity.High,
        [11211] = Severity.High,
        [27017] = Severity.High,
    };

    public static string? ServiceName(int port) => Services.GetValueOrDefault(port);

    /// <summary>
    /// Parses "22,80,443", "8000-8100", "top", or any comma-separated mix into a sorted, de-duplicated list.
    /// </summary>
    public static IReadOnlyList<int> Parse(string spec)
    {
        var ports = new SortedSet<int>();
        foreach (var part in spec.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.Equals("top", StringComparison.OrdinalIgnoreCase))
            {
                ports.UnionWith(Top);
                continue;
            }

            var dash = part.IndexOf('-');
            if (dash > 0)
            {
                var low = ParsePort(part[..dash]);
                var high = ParsePort(part[(dash + 1)..]);
                if (low > high)
                {
                    throw new FormatException($"Invalid port range '{part}': start is greater than end.");
                }

                for (var p = low; p <= high; p++)
                {
                    ports.Add(p);
                }
            }
            else
            {
                ports.Add(ParsePort(part));
            }
        }

        if (ports.Count == 0)
        {
            throw new FormatException("No ports were specified.");
        }

        return [.. ports];
    }

    /// <summary>
    /// Does a firewall rule's port expression ("any", "80,443", "5000-5010", "RPC") cover the given port?
    /// Named Windows port keywords are treated as not matching a specific number.
    /// </summary>
    public static bool RuleCovers(string rulePorts, int port)
    {
        if (IsAny(rulePorts))
        {
            return true;
        }

        foreach (var part in rulePorts.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var dash = part.IndexOf('-');
            if (dash > 0)
            {
                if (int.TryParse(part[..dash], out var low) && int.TryParse(part[(dash + 1)..], out var high) && port >= low && port <= high)
                {
                    return true;
                }
            }
            else if (int.TryParse(part, out var single) && single == port)
            {
                return true;
            }
        }

        return false;
    }

    public static bool IsAny(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return true;
        }

        var v = value.Trim();
        return v.Equals("any", StringComparison.OrdinalIgnoreCase)
            || v == "*"
            || v.Equals("anywhere", StringComparison.OrdinalIgnoreCase)
            || v == "0.0.0.0/0"
            || v == "::/0"
            || v.Equals("internet", StringComparison.OrdinalIgnoreCase);
    }

    private static int ParsePort(string text)
    {
        if (!int.TryParse(text.Trim(), out var port) || port < 1 || port > 65535)
        {
            throw new FormatException($"Invalid port '{text}'. Ports must be between 1 and 65535.");
        }

        return port;
    }
}
