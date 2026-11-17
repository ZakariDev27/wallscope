using FirewallDetector.Core.Infrastructure;
using FirewallDetector.Core.Local;
using FirewallDetector.Core.Models;
using Xunit;

namespace FirewallDetector.Tests;

public class WindowsFirewallParsingTests
{
    private const string Sample = """
        {
          "profiles": [
            { "Name": "Domain", "Enabled": "True", "DefaultInboundAction": "NotConfigured", "DefaultOutboundAction": "NotConfigured" },
            { "Name": "Private", "Enabled": "True", "DefaultInboundAction": "Block", "DefaultOutboundAction": "Allow" },
            { "Name": "Public", "Enabled": "False", "DefaultInboundAction": "Allow", "DefaultOutboundAction": "Allow" }
          ],
          "rules": [
            { "Name": "Remote Desktop", "Profile": "Any", "Protocol": "TCP", "LocalPort": "3389", "RemoteAddress": "Any", "Program": "Any" },
            { "Name": "File Sharing", "Profile": "Domain, Private", "Protocol": "TCP", "LocalPort": "445", "RemoteAddress": "Any", "Program": "System" },
            { "Name": "Office app", "Profile": "Any", "Protocol": "Any", "LocalPort": "", "RemoteAddress": "Any", "Program": "C:\\app.exe" },
            { "Name": "Wide open", "Profile": "Public", "Protocol": "TCP", "LocalPort": "Any", "RemoteAddress": "Any", "Program": "" },
            { "Name": "Scoped SSH", "Profile": "Any", "Protocol": "TCP", "LocalPort": "22", "RemoteAddress": "10.0.0.0/8", "Program": "" }
          ],
          "products": { "Name": "Acme Shield", "State": "266256" }
        }
        """;

    [Fact]
    public void Parses_profiles_rules_and_third_party_products()
    {
        var backends = WindowsFirewallProvider.Parse(Sample);

        Assert.Equal(2, backends.Count);
        var defender = backends[0];
        Assert.Equal(BackendState.Active, defender.State);
        Assert.Equal(3, defender.Profiles.Count);
        Assert.Equal("block", defender.Profiles[0].DefaultInbound);
        Assert.Equal("allow", defender.Profiles[0].DefaultOutbound);
        Assert.False(defender.Profiles[2].Enabled);
        Assert.Equal(5, defender.Rules.Count);
        Assert.Null(defender.Rules[0].Program);
        Assert.Equal("any", defender.Rules[2].LocalPorts);

        Assert.Equal("third-party: Acme Shield", backends[1].Name);
        Assert.Equal(BackendState.Active, backends[1].State);
    }

    [Fact]
    public void All_profiles_disabled_means_inactive()
    {
        var json = """{"profiles":{"Name":"Public","Enabled":"False","DefaultInboundAction":"Block","DefaultOutboundAction":"Allow"},"rules":[],"products":[]}""";
        var backend = Assert.Single(WindowsFirewallProvider.Parse(json));
        Assert.Equal(BackendState.Inactive, backend.State);
    }

    [Fact]
    public void Analyzer_flags_disabled_profile_and_risky_rules_only()
    {
        var audit = new LocalAuditResult
        {
            Platform = "windows",
            Backends = WindowsFirewallProvider.Parse(Sample),
            FirewallActive = true,
        };

        var findings = LocalAuditAnalyzer.Analyze(audit);

        var disabled = Assert.Single(findings, f => f.Id == "LOCAL-002");
        Assert.Equal(Severity.Critical, disabled.Severity);

        var sensitive = findings.Where(f => f.Id == "LOCAL-004").ToList();
        Assert.Equal(2, sensitive.Count);
        Assert.Contains(sensitive, f => f.Evidence["rule"] == "Remote Desktop" && f.Severity == Severity.High);
        // Domain/Private-only rules are downgraded one level.
        Assert.Contains(sensitive, f => f.Evidence["rule"] == "File Sharing" && f.Severity == Severity.Medium);

        var wide = Assert.Single(findings, f => f.Id == "LOCAL-005");
        Assert.Equal("Wide open", wide.Evidence["rule"]);

        // App-scoped and source-restricted rules are not findings.
        Assert.DoesNotContain(findings, f => f.Evidence.TryGetValue("rule", out var r) && r is "Office app" or "Scoped SSH");
    }

    [Theory]
    [InlineData("266256", true)]
    [InlineData("262144", false)]
    [InlineData("not-a-number", false)]
    public void Decodes_security_center_state(string state, bool expected) =>
        Assert.Equal(expected, WindowsFirewallProvider.IsSecurityCenterProductOn(state));
}

public class LinuxParsingTests
{
    [Fact]
    public void Iptables_default_drop_is_active_and_skips_conditional_accepts()
    {
        var backend = IptablesProvider.Parse("""
            -P INPUT DROP
            -P FORWARD DROP
            -P OUTPUT ACCEPT
            -A INPUT -i lo -j ACCEPT
            -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
            -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
            -A INPUT -s 10.0.0.0/8 -p tcp -m tcp --dport 5432 -j ACCEPT
            -A INPUT -p tcp -m multiport --dports 8000:8100 -j ACCEPT
            """);

        Assert.Equal(BackendState.Active, backend.State);
        Assert.Equal("block", Assert.Single(backend.Profiles).DefaultInbound);
        Assert.Equal(3, backend.Rules.Count);
        Assert.Equal("22", backend.Rules[0].LocalPorts);
        Assert.Equal("10.0.0.0/8", backend.Rules[1].RemoteAddresses);
        Assert.Equal("8000-8100", backend.Rules[2].LocalPorts);
    }

    [Fact]
    public void Iptables_accept_all_with_no_rules_is_inactive()
    {
        var backend = IptablesProvider.Parse("-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n");
        Assert.Equal(BackendState.Inactive, backend.State);
    }

    [Fact]
    public void Nftables_parses_policy_ports_and_ignores_conditional_rules()
    {
        var backend = NftablesProvider.Parse("""
            {"nftables":[
              {"metainfo":{"version":"1.0.9"}},
              {"table":{"family":"inet","name":"filter"}},
              {"chain":{"family":"inet","table":"filter","name":"input","type":"filter","hook":"input","prio":0,"policy":"drop"}},
              {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
                {"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}},
              {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":{"set":[22,{"range":[8000,8100]}]}}},{"accept":null}]}},
              {"rule":{"family":"inet","table":"filter","chain":"input","expr":[
                {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":{"prefix":{"addr":"10.0.0.0","len":8}}}},
                {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":3306}},{"accept":null}]}}
            ]}
            """);

        Assert.Equal(BackendState.Active, backend.State);
        Assert.Equal("block", Assert.Single(backend.Profiles).DefaultInbound);
        Assert.Equal(2, backend.Rules.Count);
        Assert.Equal("22,8000-8100", backend.Rules[0].LocalPorts);
        Assert.Equal("10.0.0.0/8", backend.Rules[1].RemoteAddresses);
        Assert.Equal("3306", backend.Rules[1].LocalPorts);
    }

    [Fact]
    public void Nftables_empty_ruleset_is_inactive() =>
        Assert.Equal(BackendState.Inactive, NftablesProvider.Parse("""{"nftables":[{"metainfo":{"version":"1.0.9"}}]}""").State);

    [Fact]
    public void Ufw_parses_status_defaults_and_rules()
    {
        var backend = UfwProvider.Parse("""
            Status: active
            Logging: on (low)
            Default: deny (incoming), allow (outgoing), disabled (routed)
            New profiles: skip

            To                         Action      From
            --                         ------      ----
            22/tcp                     ALLOW IN    Anywhere
            3306/tcp                   ALLOW IN    10.0.0.0/8
            23/tcp                     DENY IN     Anywhere
            22/tcp (v6)                ALLOW IN    Anywhere (v6)
            """);

        Assert.Equal(BackendState.Active, backend.State);
        Assert.Equal("block", Assert.Single(backend.Profiles).DefaultInbound);
        Assert.Equal(4, backend.Rules.Count);
        Assert.Equal("22", backend.Rules[0].LocalPorts);
        Assert.Equal("tcp", backend.Rules[0].Protocol);
        Assert.Equal("any", backend.Rules[0].RemoteAddresses);
        Assert.Equal("10.0.0.0/8", backend.Rules[1].RemoteAddresses);
        Assert.Equal(RuleAction.Block, backend.Rules[2].Action);
        Assert.Equal("any", backend.Rules[3].RemoteAddresses);
    }

    [Fact]
    public void Ufw_inactive_reports_no_rules() =>
        Assert.Equal(BackendState.Inactive, UfwProvider.Parse("Status: inactive\n").State);

    [Fact]
    public void Firewalld_maps_services_and_ports()
    {
        var backend = FirewalldProvider.ParseListAll("""
            public (active)
              target: default
              interfaces: eth0
              services: dhcpv6-client ssh
              ports: 8080/tcp 5900/tcp
              masquerade: no
            """);

        Assert.Equal(BackendState.Active, backend.State);
        Assert.Equal("block", Assert.Single(backend.Profiles).DefaultInbound);
        Assert.Equal(4, backend.Rules.Count);
        Assert.Contains(backend.Rules, r => r.Name == "service: ssh" && r.LocalPorts == "22");
        Assert.Contains(backend.Rules, r => r.LocalPorts == "5900" && r.Protocol == "tcp");
    }
}

public class LocalAuditorTests
{
    private sealed class FakeRunner(Dictionary<string, CommandResult> responses) : ICommandRunner
    {
        public Task<CommandResult> RunAsync(string fileName, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct = default) =>
            Task.FromResult(responses.GetValueOrDefault(fileName, CommandResult.NotFound));
    }

    private static CommandResult Ok(string stdout) => new(0, stdout, "", Started: true, TimedOut: false);

    private static CommandResult Denied() => new(1, "", "Operation not permitted (you must be root)", Started: true, TimedOut: false);

    [Fact]
    public async Task No_firewall_tooling_enforcing_is_a_critical_finding()
    {
        var runner = new FakeRunner(new() { ["iptables"] = Ok("-P INPUT ACCEPT\n") });
        var auditor = new LocalAuditor(LocalAuditor.ProvidersFor(HostPlatform.Linux, runner), "linux");

        var audit = await auditor.AuditAsync();

        Assert.True(audit.FirewallActive == false);
        Assert.Contains(LocalAuditAnalyzer.Analyze(audit), f => f.Id == "LOCAL-001" && f.Severity == Severity.Critical);
    }

    [Fact]
    public async Task Unreadable_ruleset_is_unknown_not_inactive()
    {
        var runner = new FakeRunner(new() { ["nft"] = Denied(), ["iptables"] = Denied() });
        var auditor = new LocalAuditor(LocalAuditor.ProvidersFor(HostPlatform.Linux, runner), "linux");

        var audit = await auditor.AuditAsync();

        Assert.Null(audit.FirewallActive);
        var findings = LocalAuditAnalyzer.Analyze(audit);
        Assert.Contains(findings, f => f.Id == "LOCAL-006");
        Assert.DoesNotContain(findings, f => f.Id == "LOCAL-001");
    }

    [Fact]
    public async Task Ufw_falls_back_to_config_file_without_root()
    {
        var runner = new FakeRunner(new() { ["ufw"] = Denied() });
        var provider = new UfwProvider(runner, path => path == "/etc/ufw/ufw.conf" ? "# comment\nENABLED=yes\nLOGLEVEL=low\n" : null);

        var backend = Assert.Single(await provider.InspectAsync());

        Assert.Equal(BackendState.Active, backend.State);
    }

    [Fact]
    public async Task Exposed_telnet_on_ufw_is_critical()
    {
        var runner = new FakeRunner(new()
        {
            ["ufw"] = Ok("Status: active\nDefault: deny (incoming), allow (outgoing)\n\n23/tcp                     ALLOW IN    Anywhere\n"),
        });
        var auditor = new LocalAuditor(LocalAuditor.ProvidersFor(HostPlatform.Linux, runner), "linux");

        var findings = LocalAuditAnalyzer.Analyze(await auditor.AuditAsync());

        Assert.Contains(findings, f => f.Id == "LOCAL-004" && f.Severity == Severity.Critical);
    }
}
