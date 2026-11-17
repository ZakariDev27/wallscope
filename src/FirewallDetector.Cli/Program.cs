using FirewallDetector.Core;
using FirewallDetector.Core.Models;
using FirewallDetector.Core.Network;
using FirewallDetector.Core.Waf;

namespace FirewallDetector.Cli;

public static class Program
{
    private const int ExitOk = 0;
    private const int ExitError = 1;
    private const int ExitFindings = 2;

    private const string Usage = """
        WallScope - firewall detection engine
        By ZaKari Perry

        Usage:
          wallscope local                         Audit this machine's firewall
          wallscope probe --targets <hosts>       Detect packet filtering in front of hosts
          wallscope waf   --urls <urls>           Identify web application firewalls
          wallscope scan  [--local] [--targets <hosts>] [--urls <urls>]   Run several modules at once

        Options:
          --targets <a,b>        Hosts or IP addresses to probe
          --ports <spec>         Ports, e.g. "top", "22,80,443", "8000-8100" (default: top)
          --timeout <ms>         Per-connection timeout in milliseconds (default: 1500)
          --concurrency <n>      Parallel connections per host (default: 32)
          --urls <a,b>           URLs to check for a WAF
          --passive              WAF: fingerprint the normal response only, send no test request
          --insecure             WAF: accept invalid TLS certificates
          --signatures <file>    WAF: use a custom signature catalog
          --format <json|text>   Output format (default: text)
          --output <file>        Also write the JSON report to a file
          --fail-on <severity>   Exit with code 2 if a finding at or above info|low|medium|high|critical exists
          --authorized           Confirm you own or are permitted to test every remote target
          -h, --help             Show this help

        Remote targets are only scanned with --authorized. Loopback targets never need it.
        """;

    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 0 || args.Contains("-h") || args.Contains("--help"))
        {
            Console.WriteLine(Usage);
            return args.Length == 0 ? ExitError : ExitOk;
        }

        using var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };

        try
        {
            return await RunAsync(args, cts.Token).ConfigureAwait(false);
        }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine("error: " + ex.Message);
            Console.Error.WriteLine("Run 'wallscope --help' for usage.");
            return ExitError;
        }
        catch (FormatException ex)
        {
            Console.Error.WriteLine("error: " + ex.Message);
            return ExitError;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("cancelled");
            return ExitError;
        }
    }

    private static async Task<int> RunAsync(string[] args, CancellationToken ct)
    {
        var command = args[0].ToLowerInvariant();
        var parsed = Arguments.Parse(args[1..]);

        var targets = parsed.List("targets");
        var urls = parsed.List("urls");
        var local = parsed.Flag("local");

        switch (command)
        {
            case "local":
                local = true;
                targets = [];
                urls = [];
                break;
            case "probe":
                Require(targets.Count > 0, "probe needs --targets.");
                local = false;
                urls = [];
                break;
            case "waf":
                Require(urls.Count > 0, "waf needs --urls.");
                local = false;
                targets = [];
                break;
            case "scan":
                Require(local || targets.Count > 0 || urls.Count > 0, "scan needs at least one of --local, --targets, --urls.");
                break;
            default:
                throw new ArgumentException($"Unknown command '{args[0]}'.");
        }

        var remote = TargetPolicy.RemoteTargets(targets.Concat(urls));
        if (remote.Count > 0 && !parsed.Flag("authorized"))
        {
            Console.Error.WriteLine("error: these targets are not on this machine: " + string.Join(", ", remote));
            Console.Error.WriteLine("Only scan systems you own or have written permission to test. Add --authorized to confirm.");
            return ExitError;
        }

        var wafOptions = new WafOptions
        {
            ActiveProbe = !parsed.Flag("passive"),
            AllowInvalidCertificates = parsed.Flag("insecure"),
        };
        var catalogPath = parsed.Value("signatures");
        var detector = new WafDetector(catalogPath is null ? null : WafSignatureCatalog.LoadFile(catalogPath));

        var options = new ScanOptions
        {
            LocalAudit = local,
            Targets = targets,
            Urls = urls,
            Ports = PortCatalog.Parse(parsed.Value("ports") ?? "top"),
            Probe = new ProbeOptions
            {
                Timeout = TimeSpan.FromMilliseconds(parsed.Int("timeout", 1500, 100, 60_000)),
                Concurrency = parsed.Int("concurrency", 32, 1, 256),
            },
            Waf = wafOptions,
        };

        var format = (parsed.Value("format") ?? "text").ToLowerInvariant();
        Require(format is "json" or "text", "--format must be json or text.");

        Severity? failOn = null;
        if (parsed.Value("fail-on") is { } failText)
        {
            Require(Enum.TryParse<Severity>(failText, ignoreCase: true, out var severity) && Enum.IsDefined(severity),
                "--fail-on must be one of info, low, medium, high, critical.");
            failOn = severity;
        }

        var report = await new ScanEngine(waf: detector).RunAsync(options, ct).ConfigureAwait(false);
        var json = ReportSerializer.ToJson(report);

        if (parsed.Value("output") is { } outputPath)
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(outputPath));
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            await File.WriteAllTextAsync(outputPath, json, ct).ConfigureAwait(false);
        }

        Console.WriteLine(format == "json" ? json : ReportSerializer.ToText(report));

        return failOn is { } threshold && report.Findings.Any(f => f.Severity >= threshold) ? ExitFindings : ExitOk;
    }

    private static void Require(bool condition, string message)
    {
        if (!condition)
        {
            throw new ArgumentException(message);
        }
    }
}

/// <summary>Minimal "--name value" / "--flag" parser.</summary>
public sealed class Arguments
{
    private static readonly HashSet<string> Flags = new(StringComparer.Ordinal) { "local", "passive", "insecure", "authorized" };
    private static readonly HashSet<string> Valued = new(StringComparer.Ordinal)
    {
        "targets", "ports", "timeout", "concurrency", "urls", "signatures", "format", "output", "fail-on",
    };

    private readonly Dictionary<string, string> _values = new(StringComparer.Ordinal);
    private readonly HashSet<string> _flags = new(StringComparer.Ordinal);

    public static Arguments Parse(string[] args)
    {
        var parsed = new Arguments();
        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];
            if (!arg.StartsWith("--", StringComparison.Ordinal))
            {
                throw new ArgumentException($"Unexpected argument '{arg}'.");
            }

            var name = arg[2..];
            if (Flags.Contains(name))
            {
                parsed._flags.Add(name);
            }
            else if (Valued.Contains(name))
            {
                if (i + 1 >= args.Length)
                {
                    throw new ArgumentException($"Option '{arg}' needs a value.");
                }

                parsed._values[name] = args[++i];
            }
            else
            {
                throw new ArgumentException($"Unknown option '{arg}'.");
            }
        }

        return parsed;
    }

    public bool Flag(string name) => _flags.Contains(name);

    public string? Value(string name) => _values.GetValueOrDefault(name);

    public IReadOnlyList<string> List(string name) =>
        Value(name)?.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? [];

    public int Int(string name, int fallback, int min, int max)
    {
        if (Value(name) is not { } text)
        {
            return fallback;
        }

        if (!int.TryParse(text, out var value) || value < min || value > max)
        {
            throw new ArgumentException($"--{name} must be a number between {min} and {max}.");
        }

        return value;
    }
}
