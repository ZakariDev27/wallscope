using System.Net;
using FirewallDetector.Core;
using FirewallDetector.Core.Models;
using FirewallDetector.Core.Network;
using FirewallDetector.Core.Waf;
using Xunit;

namespace FirewallDetector.Tests;

public class PortCatalogTests
{
    [Fact]
    public void Parses_lists_ranges_and_presets()
    {
        Assert.Equal(new[] { 22, 80, 443 }, PortCatalog.Parse("443, 22,80,22").ToArray());
        Assert.Equal(new[] { 8000, 8001, 8002 }, PortCatalog.Parse("8000-8002").ToArray());
        Assert.Contains(3389, PortCatalog.Parse("top"));
    }

    [Theory]
    [InlineData("0")]
    [InlineData("70000")]
    [InlineData("abc")]
    [InlineData("90-80")]
    [InlineData("")]
    public void Rejects_invalid_specs(string spec) =>
        Assert.Throws<FormatException>(() => PortCatalog.Parse(spec));

    [Theory]
    [InlineData("any", 3389, true)]
    [InlineData("80,443", 443, true)]
    [InlineData("3000-4000", 3389, true)]
    [InlineData("80,443", 22, false)]
    [InlineData("RPC", 135, false)]
    public void Rule_port_coverage(string rulePorts, int port, bool expected) =>
        Assert.Equal(expected, PortCatalog.RuleCovers(rulePorts, port));
}

public class FilteringTests
{
    private sealed class ScriptedConnector(Dictionary<int, PortState> states) : ITcpConnector
    {
        public int Attempts;

        public Task<ConnectOutcome> ConnectAsync(IPAddress address, int port, TimeSpan timeout, CancellationToken ct = default)
        {
            Interlocked.Increment(ref Attempts);
            var state = states.GetValueOrDefault(port, PortState.Filtered);
            var reason = state switch { PortState.Open => "syn-ack", PortState.Closed => "rst", _ => "no-response" };
            return Task.FromResult(new ConnectOutcome(state, reason, 1));
        }
    }

    private static Task<HostProbeResult> Probe(Dictionary<int, PortState> states, IReadOnlyList<int> ports, string target = "203.0.113.10") =>
        new PortProber(new ScriptedConnector(states)).ProbeAsync(target, ports);

    [Fact]
    public async Task Mixed_resets_and_silence_means_a_firewall_is_in_the_path()
    {
        var result = await Probe(new() { [80] = PortState.Open, [81] = PortState.Closed }, [80, 81, 22, 3389]);

        Assert.Equal(FilteringVerdict.FilteringDetected, result.Verdict);
        Assert.Equal((1, 1, 2), (result.Open, result.Closed, result.Filtered));
        Assert.Contains(FilteringAnalyzer.Analyze(result), f => f.Id == "NET-001");
    }

    [Fact]
    public async Task Open_plus_silence_means_default_drop()
    {
        var result = await Probe(new() { [443] = PortState.Open }, [443, 22, 23]);
        Assert.Equal(FilteringVerdict.DefaultDropLikely, result.Verdict);
    }

    [Fact]
    public async Task All_answers_means_no_filtering_observed()
    {
        var result = await Probe(new() { [80] = PortState.Open, [22] = PortState.Closed }, [80, 22]);

        Assert.Equal(FilteringVerdict.NoFilteringObserved, result.Verdict);
        Assert.Contains(FilteringAnalyzer.Analyze(result), f => f.Id == "NET-002");
    }

    [Fact]
    public async Task Total_silence_is_unreachable_or_fully_filtered()
    {
        var result = await Probe(new(), [80, 22]);
        Assert.Equal(FilteringVerdict.UnreachableOrFullyFiltered, result.Verdict);
    }

    [Fact]
    public async Task Silent_ports_are_retried_once()
    {
        var connector = new ScriptedConnector(new() { [80] = PortState.Open });
        await new PortProber(connector).ProbeAsync("203.0.113.10", [80, 81]);
        Assert.Equal(3, connector.Attempts);
    }

    [Fact]
    public async Task Sensitive_open_port_is_reported_for_remote_hosts_but_not_loopback()
    {
        var states = new Dictionary<int, PortState> { [3389] = PortState.Open, [80] = PortState.Closed };

        var remote = FilteringAnalyzer.Analyze(await Probe(states, [3389, 80]));
        var local = FilteringAnalyzer.Analyze(await Probe(states, [3389, 80], "127.0.0.1"));

        Assert.Contains(remote, f => f.Id == "NET-003" && f.Severity == Severity.High);
        Assert.DoesNotContain(local, f => f.Id == "NET-003");
    }

    [Fact]
    public async Task Unresolvable_name_is_reported_not_thrown()
    {
        var prober = new PortProber(new ScriptedConnector(new()), (_, _) => Task.FromResult(Array.Empty<IPAddress>()));
        var result = await prober.ProbeAsync("nope.invalid", [80]);

        Assert.NotNull(result.Error);
        Assert.Contains(FilteringAnalyzer.Analyze(result), f => f.Id == "NET-005");
    }

    [Fact]
    public async Task Real_socket_connector_classifies_loopback_ports()
    {
        using var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var openPort = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var closedProbe = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        closedProbe.Start();
        var closedPort = ((IPEndPoint)closedProbe.LocalEndpoint).Port;
        closedProbe.Stop();

        var connector = new SocketTcpConnector();
        var open = await connector.ConnectAsync(IPAddress.Loopback, openPort, TimeSpan.FromSeconds(2));
        var closed = await connector.ConnectAsync(IPAddress.Loopback, closedPort, TimeSpan.FromSeconds(2));

        Assert.Equal(PortState.Open, open.State);
        Assert.Equal(PortState.Closed, closed.State);
    }
}

public class WafTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(respond(request));
    }

    private static WafDetector Detector(Func<HttpRequestMessage, HttpResponseMessage> respond) =>
        new(handlerFactory: _ => new StubHandler(respond));

    private static bool IsTest(HttpRequestMessage request) => request.RequestUri!.Query.Contains("wsx=");

    private static HttpResponseMessage Response(HttpStatusCode status, string body = "<html>ok</html>", params (string Name, string Value)[] headers)
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent(body) };
        foreach (var (name, value) in headers)
        {
            response.Headers.TryAddWithoutValidation(name, value);
        }

        return response;
    }

    [Fact]
    public void Embedded_catalog_loads_and_every_pattern_compiles()
    {
        var catalog = WafSignatureCatalog.LoadEmbedded();

        Assert.True(catalog.Signatures.Count >= 15);
        foreach (var matcher in catalog.Signatures.SelectMany(s => s.Matchers))
        {
            Assert.Contains(matcher.Type, new[] { "header", "cookie", "body" });
            _ = new System.Text.RegularExpressions.Regex(matcher.Pattern);
            if (matcher.Type == "header")
            {
                Assert.False(string.IsNullOrEmpty(matcher.Name));
            }
        }
    }

    [Fact]
    public async Task Identifies_cloudflare_and_sees_blocking()
    {
        var detector = Detector(request => IsTest(request)
            ? Response(HttpStatusCode.Forbidden, "<title>Attention Required! | Cloudflare</title>", ("Server", "cloudflare"), ("CF-RAY", "8abc-IAD"))
            : Response(HttpStatusCode.OK, "<html>ok</html>", ("Server", "cloudflare"), ("CF-RAY", "8abc-IAD"), ("Set-Cookie", "__cf_bm=abc; path=/")));

        var result = await detector.DetectAsync("https://shop.example/");

        Assert.True(result.Detected);
        Assert.True(result.GenericBlockingObserved);
        Assert.Equal(403, result.ProvocationStatus);
        var match = result.Matches[0];
        Assert.Equal("Cloudflare", match.Name);
        Assert.Equal(100, match.Confidence);

        var findings = WafDetector.Analyze(result);
        Assert.Contains(findings, f => f.Id == "WAF-001");
        Assert.DoesNotContain(findings, f => f.Id is "WAF-002" or "WAF-005");
    }

    [Fact]
    public async Task Unprotected_site_yields_medium_finding()
    {
        var detector = Detector(_ => Response(HttpStatusCode.OK, "<html>ok</html>", ("Server", "nginx")));

        var result = await detector.DetectAsync("https://plain.example/");

        Assert.False(result.Detected);
        Assert.Contains(WafDetector.Analyze(result), f => f.Id == "WAF-002" && f.Severity == Severity.Medium);
    }

    [Fact]
    public async Task Unknown_product_that_blocks_is_generic_detection()
    {
        var detector = Detector(request => IsTest(request)
            ? Response(HttpStatusCode.NotAcceptable, "denied")
            : Response(HttpStatusCode.OK));

        var result = await detector.DetectAsync("https://mystery.example/");

        Assert.True(result.Detected);
        Assert.Empty(result.Matches);
        Assert.Contains(WafDetector.Analyze(result), f => f.Id == "WAF-003");
    }

    [Fact]
    public async Task Fingerprinted_but_not_blocking_raises_monitor_mode_finding()
    {
        var detector = Detector(_ => Response(HttpStatusCode.OK, "<html>ok</html>", ("X-Sucuri-ID", "14001")));

        var result = await detector.DetectAsync("https://quiet.example/");

        Assert.True(result.Detected);
        Assert.False(result.GenericBlockingObserved);
        Assert.Contains(WafDetector.Analyze(result), f => f.Id == "WAF-005");
    }

    [Fact]
    public async Task Passive_mode_sends_exactly_one_request()
    {
        var requests = 0;
        var detector = Detector(_ =>
        {
            requests++;
            return Response(HttpStatusCode.OK);
        });

        var result = await detector.DetectAsync("https://plain.example/", new WafOptions { ActiveProbe = false });

        Assert.Equal(1, requests);
        Assert.Null(result.ProvocationStatus);
        Assert.Contains(WafDetector.Analyze(result), f => f.Id == "WAF-002" && f.Severity == Severity.Low);
    }

    [Fact]
    public async Task Dropped_test_request_counts_as_blocking()
    {
        var detector = Detector(request => IsTest(request)
            ? throw new HttpRequestException("connection reset")
            : Response(HttpStatusCode.OK));

        var result = await detector.DetectAsync("https://reset.example/");

        Assert.True(result.GenericBlockingObserved);
    }

    [Theory]
    [InlineData("ftp://example.com/")]
    [InlineData("not a url")]
    public async Task Rejects_non_http_urls(string url)
    {
        var result = await Detector(_ => Response(HttpStatusCode.OK)).DetectAsync(url);
        Assert.NotNull(result.Error);
    }

    [Fact]
    public void Provocation_keeps_existing_query()
    {
        var uri = WafDetector.BuildProvocationUri(new Uri("https://a.example/search?q=1"));
        Assert.StartsWith("?q=1&wsx=", uri.Query);
    }
}

public class EngineTests
{
    [Theory]
    [InlineData("localhost", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("::1", true)]
    [InlineData("http://127.0.0.1:8080/app", true)]
    [InlineData("https://[::1]/", true)]
    [InlineData("example.com", false)]
    [InlineData("https://example.com/", false)]
    [InlineData("10.0.0.5", false)]
    public void Target_policy_separates_local_from_remote(string target, bool local) =>
        Assert.Equal(local, TargetPolicy.IsLocal(target));

    [Fact]
    public void Report_round_trips_through_json()
    {
        var report = new ScanReport
        {
            ToolVersion = "1.0.0",
            Host = "h",
            Os = "os",
            StartedUtc = DateTimeOffset.UnixEpoch,
            FinishedUtc = DateTimeOffset.UnixEpoch,
            Findings =
            [
                new Finding { Id = "NET-001", Module = "network", Severity = Severity.High, Title = "t", Detail = "d" },
            ],
        };

        var json = ReportSerializer.ToJson(report);
        var back = ReportSerializer.FromJson(json);

        Assert.Contains("\"severity\": \"high\"", json);
        Assert.Equal(Severity.High, Assert.Single(back.Findings).Severity);
    }
}
