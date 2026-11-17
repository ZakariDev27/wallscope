using System.Net;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;
using FirewallDetector.Core.Models;

namespace FirewallDetector.Core.Waf;

public sealed record WafMatcher
{
    public required string Type { get; init; }
    public string? Name { get; init; }
    public required string Pattern { get; init; }
    public int Weight { get; init; } = 30;
}

public sealed record WafSignature
{
    public required string Name { get; init; }
    public required string Vendor { get; init; }
    public string Kind { get; init; } = "waf";
    public IReadOnlyList<WafMatcher> Matchers { get; init; } = [];
}

public sealed record WafSignatureCatalog
{
    public string Version { get; init; } = "unknown";
    public IReadOnlyList<WafSignature> Signatures { get; init; } = [];

    private static readonly JsonSerializerOptions Options = new() { PropertyNameCaseInsensitive = true };

    public static WafSignatureCatalog LoadEmbedded()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("FirewallDetector.Core.Waf.waf-signatures.json")
            ?? throw new InvalidOperationException("Embedded WAF signature catalog is missing.");
        using var reader = new StreamReader(stream);
        return Parse(reader.ReadToEnd());
    }

    public static WafSignatureCatalog LoadFile(string path) => Parse(File.ReadAllText(path));

    public static WafSignatureCatalog Parse(string json) =>
        JsonSerializer.Deserialize<WafSignatureCatalog>(json, Options)
        ?? throw new JsonException("WAF signature catalog is empty.");
}

/// <summary>The parts of an HTTP response the signatures look at.</summary>
public sealed record HttpSnapshot(int Status, IReadOnlyDictionary<string, string> Headers, IReadOnlyList<string> Cookies, string Body);

public sealed record WafOptions
{
    /// <summary>When false, only the normal response is fingerprinted and no test request is sent.</summary>
    public bool ActiveProbe { get; init; } = true;
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);
    public bool AllowInvalidCertificates { get; init; }
}

/// <summary>
/// Identifies web application firewalls in front of a URL. It fingerprints a normal response, then
/// (unless passive) sends one request carrying harmless marker strings that every mainstream WAF
/// rule set blocks, and compares the two answers. The markers are inert: they are sent as an unused
/// query parameter and exploit nothing.
/// </summary>
public sealed class WafDetector
{
    public const string UserAgent = "WallScope/1.0 (authorized security assessment)";
    private const int MaxBodyBytes = 64 * 1024;
    private const int MinConfidence = 30;
    private static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(250);

    private readonly WafSignatureCatalog _catalog;
    private readonly Func<WafOptions, HttpMessageHandler> _handlerFactory;

    public WafDetector(WafSignatureCatalog? catalog = null, Func<WafOptions, HttpMessageHandler>? handlerFactory = null)
    {
        _catalog = catalog ?? WafSignatureCatalog.LoadEmbedded();
        _handlerFactory = handlerFactory ?? DefaultHandler;
    }

    public async Task<WafResult> DetectAsync(string url, WafOptions? options = null, CancellationToken ct = default)
    {
        options ??= new WafOptions();
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            return new WafResult { Url = url, Error = "Not a valid http(s) URL." };
        }

        using var client = new HttpClient(_handlerFactory(options), disposeHandler: true) { Timeout = options.Timeout };
        client.DefaultRequestHeaders.UserAgent.ParseAdd(UserAgent);
        client.DefaultRequestHeaders.Accept.ParseAdd("text/html,application/xhtml+xml,*/*;q=0.8");

        HttpSnapshot baseline;
        try
        {
            baseline = await FetchAsync(client, uri, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
        {
            ct.ThrowIfCancellationRequested();
            return new WafResult { Url = url, ActiveProbe = options.ActiveProbe, Error = "Baseline request failed: " + Describe(ex) };
        }

        HttpSnapshot? provocation = null;
        var provocationDropped = false;
        string? provocationError = null;
        if (options.ActiveProbe)
        {
            try
            {
                provocation = await FetchAsync(client, BuildProvocationUri(uri), ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException)
            {
                ct.ThrowIfCancellationRequested();
                // The normal request worked and the test request was cut off: that is itself blocking behaviour.
                provocationDropped = true;
                provocationError = Describe(ex);
            }
        }

        var matches = Match(baseline, provocation);
        var generic = provocationDropped || IsGenericBlock(baseline, provocation);
        var notes = provocationDropped
            ? "The test request was dropped while the normal request succeeded (" + provocationError + ")."
            : generic && matches.Count == 0
                ? "The test request was blocked but no known product fingerprint matched."
                : null;

        return new WafResult
        {
            Url = url,
            Reachable = true,
            ActiveProbe = options.ActiveProbe,
            BaselineStatus = baseline.Status,
            ProvocationStatus = provocation?.Status,
            Detected = matches.Count > 0 || generic,
            GenericBlockingObserved = generic,
            Matches = matches,
            Notes = notes,
        };
    }

    /// <summary>Scores every signature against the captured responses.</summary>
    public IReadOnlyList<WafMatch> Match(HttpSnapshot baseline, HttpSnapshot? provocation)
    {
        var matches = new List<WafMatch>();
        foreach (var signature in _catalog.Signatures)
        {
            var evidence = new List<string>();
            var score = 0;
            foreach (var matcher in signature.Matchers)
            {
                var hit = Evaluate(matcher, baseline, "normal response")
                    ?? (provocation is null ? null : Evaluate(matcher, provocation, "test response"));
                if (hit is not null)
                {
                    evidence.Add(hit);
                    score += matcher.Weight;
                }
            }

            if (score >= MinConfidence)
            {
                matches.Add(new WafMatch
                {
                    Name = signature.Name,
                    Vendor = signature.Vendor,
                    Kind = signature.Kind,
                    Confidence = Math.Min(100, score),
                    Evidence = evidence,
                });
            }
        }

        return [.. matches.OrderByDescending(m => m.Confidence)];
    }

    public static bool IsGenericBlock(HttpSnapshot baseline, HttpSnapshot? provocation)
    {
        if (provocation is null || baseline.Status >= 400)
        {
            return false;
        }

        // The page loads normally, but the same page with test markers is refused.
        return provocation.Status is 403 or 406 or 409 or 418 or 419 or 429 or 444 or 451 or 493 or 501 or 503 or 999;
    }

    public static Uri BuildProvocationUri(Uri uri)
    {
        // Classic, inert markers for cross-site scripting, SQL injection and path traversal rules.
        string[] markers =
        [
            "wsx=" + Uri.EscapeDataString("<script>alert('wallscope')</script>"),
            "wsq=" + Uri.EscapeDataString("' OR '1'='1' -- "),
            "wsp=" + Uri.EscapeDataString("../../../../etc/passwd"),
        ];
        var builder = new UriBuilder(uri);
        var existing = builder.Query.TrimStart('?');
        builder.Query = existing.Length > 0 ? existing + "&" + string.Join("&", markers) : string.Join("&", markers);
        return builder.Uri;
    }

    public static IReadOnlyList<Finding> Analyze(WafResult result)
    {
        const string module = "waf";
        if (result.Error is not null)
        {
            return
            [
                new Finding
                {
                    Id = "WAF-004",
                    Module = module,
                    Severity = Severity.Low,
                    Target = result.Url,
                    Title = "URL could not be checked",
                    Detail = result.Error,
                },
            ];
        }

        var findings = new List<Finding>();
        foreach (var match in result.Matches)
        {
            findings.Add(new Finding
            {
                Id = "WAF-001",
                Module = module,
                Severity = Severity.Info,
                Target = result.Url,
                Title = $"{match.Name} detected ({match.Confidence}% confidence)",
                Detail = $"Fingerprints for {match.Name} by {match.Vendor} matched: {string.Join("; ", match.Evidence)}.",
                Evidence = new Dictionary<string, string>
                {
                    ["product"] = match.Name,
                    ["kind"] = match.Kind,
                    ["confidence"] = match.Confidence.ToString(),
                },
            });
        }

        if (result.GenericBlockingObserved && result.Matches.Count == 0)
        {
            findings.Add(new Finding
            {
                Id = "WAF-003",
                Module = module,
                Severity = Severity.Info,
                Target = result.Url,
                Title = "Unidentified WAF behaviour",
                Detail = result.Notes ?? "The test request was blocked but the product could not be identified.",
                Evidence = Statuses(result),
            });
        }

        if (!result.Detected)
        {
            findings.Add(new Finding
            {
                Id = "WAF-002",
                Module = module,
                Severity = result.ActiveProbe ? Severity.Medium : Severity.Low,
                Target = result.Url,
                Title = result.ActiveProbe ? "No web application firewall detected" : "No WAF fingerprint observed (passive check)",
                Detail = result.ActiveProbe
                    ? "No known WAF fingerprint matched and a request carrying common attack markers was served normally."
                    : "No known WAF fingerprint matched the normal response. A passive check cannot rule out a quiet WAF.",
                Remediation = "Place internet-facing web applications behind a WAF, or confirm blocking mode is enabled on the existing one.",
                Evidence = Statuses(result),
            });
        }
        else if (result.ActiveProbe && !result.GenericBlockingObserved && result.Matches.Any(m => m.Kind != "bot-management"))
        {
            findings.Add(new Finding
            {
                Id = "WAF-005",
                Module = module,
                Severity = Severity.Low,
                Target = result.Url,
                Title = "WAF present but the test request was not blocked",
                Detail = "A WAF or CDN was fingerprinted, yet a request carrying common attack markers was served normally. It may be in monitor-only mode or have its managed rules switched off.",
                Remediation = "Check that the WAF policy is in blocking mode and that core rule sets are enabled for this hostname.",
                Evidence = Statuses(result),
            });
        }

        return findings;
    }

    private static Dictionary<string, string> Statuses(WafResult result)
    {
        var evidence = new Dictionary<string, string>();
        if (result.BaselineStatus is { } baseline)
        {
            evidence["normalStatus"] = baseline.ToString();
        }

        if (result.ProvocationStatus is { } provocation)
        {
            evidence["testStatus"] = provocation.ToString();
        }

        return evidence;
    }

    private static string? Evaluate(WafMatcher matcher, HttpSnapshot snapshot, string label)
    {
        try
        {
            switch (matcher.Type.ToLowerInvariant())
            {
                case "header":
                    if (matcher.Name is not null
                        && snapshot.Headers.TryGetValue(matcher.Name, out var value)
                        && Regex.IsMatch(value, matcher.Pattern, RegexOptions.IgnoreCase, RegexTimeout))
                    {
                        return $"header {matcher.Name.ToLowerInvariant()} in {label}";
                    }

                    break;
                case "cookie":
                    foreach (var cookie in snapshot.Cookies)
                    {
                        if (Regex.IsMatch(cookie, matcher.Pattern, RegexOptions.IgnoreCase, RegexTimeout))
                        {
                            var name = cookie.Split('=', 2)[0];
                            return $"cookie {name} in {label}";
                        }
                    }

                    break;
                case "body":
                    if (Regex.IsMatch(snapshot.Body, matcher.Pattern, RegexOptions.IgnoreCase, RegexTimeout))
                    {
                        return $"block-page text in {label}";
                    }

                    break;
            }
        }
        catch (RegexMatchTimeoutException)
        {
            // A pathological page must not stall the scan; treat as no match.
        }

        return null;
    }

    private static async Task<HttpSnapshot> FetchAsync(HttpClient client, Uri uri, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        using var response = await client.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var cookies = new List<string>();
        foreach (var header in response.Headers.Concat(response.Content.Headers))
        {
            if (header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            {
                cookies.AddRange(header.Value);
            }
            else
            {
                headers[header.Key] = string.Join(", ", header.Value);
            }
        }

        var body = await ReadLimitedAsync(response.Content, ct).ConfigureAwait(false);
        return new HttpSnapshot((int)response.StatusCode, headers, cookies, body);
    }

    private static async Task<string> ReadLimitedAsync(HttpContent content, CancellationToken ct)
    {
        await using var stream = await content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        var buffer = new byte[MaxBodyBytes];
        var total = 0;
        while (total < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(total, buffer.Length - total), ct).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
        }

        return System.Text.Encoding.UTF8.GetString(buffer, 0, total);
    }

    private static HttpMessageHandler DefaultHandler(WafOptions options)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 5,
            AutomaticDecompression = DecompressionMethods.All,
            UseCookies = false,
            ConnectTimeout = options.Timeout,
        };
        if (options.AllowInvalidCertificates)
        {
            handler.SslOptions.RemoteCertificateValidationCallback = (_, _, _, _) => true;
        }

        return handler;
    }

    private static string Describe(Exception ex) =>
        ex is TaskCanceledException ? "request timed out" : (ex.InnerException?.Message ?? ex.Message);
}
