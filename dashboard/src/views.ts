// Renders the result tabs. Pure functions from report data to DOM nodes.

import {
  SEVERITIES,
  type Drift,
  type Finding,
  type HostProbe,
  type LocalAudit,
  type ReportSummary,
  type Severity,
  type WafResult,
} from "./api.js";
import { formatWhen, h, stagger } from "./dom.js";

export interface ViewActions {
  askScout: (question: string) => void;
  openReport: (id: string) => void;
  compareWith: (id: string) => void;
}

const VERDICT_TEXT: Record<string, string> = {
  filteringDetected: "Firewall detected",
  defaultDropLikely: "Default-drop firewall likely",
  noFilteringObserved: "No filtering observed",
  unreachableOrFullyFiltered: "Unreachable or fully filtered",
  inconclusive: "Inconclusive",
};

function badge(severity: Severity): HTMLElement {
  return h("span", { class: `sev sev-${severity}` }, severity);
}

function emptyNote(text: string): HTMLElement {
  return h("p", { class: "muted pad" }, text);
}

// ---------- findings ----------

export function findingsView(findings: Finding[], actions: ViewActions): HTMLElement {
  const root = h("div");
  if (findings.length === 0) {
    root.append(emptyNote("No findings. Nothing in this scan needs attention."));
    return root;
  }

  const active = new Set<Severity>(SEVERITIES);
  const filters = h("div", { class: "filters" });
  const list = h("div", { class: "finding-list" });

  const render = (): void => {
    list.replaceChildren();
    const visible = findings.filter((finding) => active.has(finding.severity));
    if (visible.length === 0) list.append(emptyNote("Every severity is filtered out."));
    const cards = visible.map((finding) => findingCard(finding, actions));
    list.append(...cards);
    stagger(cards);
  };

  for (const severity of SEVERITIES) {
    const count = findings.filter((finding) => finding.severity === severity).length;
    if (count === 0) continue;
    const button = h("button", { class: `filter sev-${severity} on`, type: "button", "aria-pressed": "true" }, `${severity} ${count}`);
    button.addEventListener("click", () => {
      const on = !active.has(severity);
      if (on) active.add(severity);
      else active.delete(severity);
      button.classList.toggle("on", on);
      button.setAttribute("aria-pressed", String(on));
      render();
    });
    filters.append(button);
  }

  root.append(filters, list);
  render();
  return root;
}

function findingCard(finding: Finding, actions: ViewActions): HTMLElement {
  const body = h(
    "div",
    { class: "finding-body" },
    h("p", {}, finding.detail),
    finding.remediation ? h("p", { class: "fix" }, h("b", {}, "Fix: "), finding.remediation) : null,
  );

  const evidence = Object.entries(finding.evidence ?? {});
  if (evidence.length > 0) {
    const table = h("dl", { class: "evidence" });
    for (const [key, value] of evidence) table.append(h("dt", {}, key), h("dd", {}, value));
    body.append(table);
  }

  const ask = h("button", { class: "ghost small", type: "button" }, "Ask Scout");
  ask.addEventListener("click", (event) => {
    event.stopPropagation();
    actions.askScout(`Explain ${finding.id}`);
  });
  body.append(ask);

  const toggle = h(
    "button",
    { class: "finding-head", type: "button", "aria-expanded": "false" },
    badge(finding.severity),
    h("span", { class: "finding-title" }, finding.title),
    h("code", {}, finding.id),
    h("span", { class: "chevron", "aria-hidden": "true" }),
  );
  const card = h(
    "article",
    { class: `finding sev-edge-${finding.severity}` },
    toggle,
    finding.target ? h("div", { class: "finding-target" }, finding.target) : null,
    h("div", { class: "finding-collapse" }, body),
  );
  toggle.addEventListener("click", () => {
    const open = card.classList.toggle("open");
    toggle.setAttribute("aria-expanded", String(open));
  });
  return card;
}

// ---------- network ----------

export function networkView(probes: HostProbe[]): HTMLElement {
  const root = h("div");
  if (probes.length === 0) {
    root.append(emptyNote("This scan did not probe any hosts. Use \"Probe host\" on the left."));
    return root;
  }

  const cards = probes.map((probe) => {
    const card = h("article", { class: "block" });
    card.append(
      h(
        "header",
        { class: "block-head" },
        h("div", {}, h("h3", {}, probe.target), h("span", { class: "muted" }, probe.resolvedAddress ?? "unresolved")),
        h("span", { class: `verdict verdict-${probe.verdict}` }, VERDICT_TEXT[probe.verdict] ?? probe.verdict),
      ),
    );

    if (probe.error) {
      card.append(h("p", { class: "muted" }, probe.error));
      return card;
    }

    const total = Math.max(1, probe.ports.length);
    const bar = h("div", { class: "state-bar", role: "img", "aria-label": `${probe.open} open, ${probe.closed} closed, ${probe.filtered} filtered` });
    for (const [state, count] of [["open", probe.open], ["closed", probe.closed], ["filtered", probe.filtered]] as const) {
      if (count === 0) continue;
      const segment = h("span", { class: `seg seg-${state}` });
      segment.style.flexGrow = String(count / total);
      bar.append(segment);
    }
    card.append(
      bar,
      h(
        "div",
        { class: "legend" },
        h("span", {}, h("i", { class: "key seg-open" }), `${probe.open} open`),
        h("span", {}, h("i", { class: "key seg-closed" }), `${probe.closed} closed`),
        h("span", {}, h("i", { class: "key seg-filtered" }), `${probe.filtered} filtered`),
      ),
    );

    const grid = h("div", { class: "port-grid" });
    const cells = probe.ports.map((port) =>
      h(
        "div",
        { class: `port port-${port.state}`, title: `${port.port}/tcp ${port.state} (${port.reason})` },
        h("b", {}, String(port.port)),
        h("span", {}, port.service ?? "tcp"),
      ),
    );
    grid.append(...cells);
    stagger(cells, 18);
    card.append(grid, h("p", { class: "muted" }, probe.explanation));
    return card;
  });

  root.append(...cards);
  stagger(cards, 90);
  return root;
}

// ---------- websites ----------

export function webView(results: WafResult[]): HTMLElement {
  const root = h("div");
  if (results.length === 0) {
    root.append(emptyNote("This scan did not check any websites. Use \"Check website\" on the left."));
    return root;
  }

  const cards = results.map((result) => {
    const card = h("article", { class: "block" });
    const state = result.error ? "error" : result.detected ? "protected" : "unprotected";
    const label = result.error ? "Could not check" : result.detected ? "WAF detected" : "No WAF detected";
    card.append(
      h(
        "header",
        { class: "block-head" },
        h("div", {}, h("h3", { class: "break" }, result.url), h("span", { class: "muted" }, result.activeProbe ? "Active check" : "Passive check")),
        h("span", { class: `verdict waf-${state}` }, label),
      ),
    );

    if (result.error) {
      card.append(h("p", { class: "muted" }, result.error));
      return card;
    }

    for (const match of result.matches) {
      const meter = h("div", { class: "meter" }, h("span", {}));
      const fill = meter.firstElementChild as HTMLElement;
      // Start at zero and widen on the next frame so the bar visibly fills.
      requestAnimationFrame(() => requestAnimationFrame(() => (fill.style.width = `${match.confidence}%`)));
      card.append(
        h(
          "div",
          { class: "waf-match" },
          h("div", { class: "waf-name" }, h("b", {}, match.name), h("span", { class: "muted" }, `${match.vendor} · ${match.kind}`)),
          h("div", { class: "waf-confidence" }, meter, h("span", {}, `${match.confidence}%`)),
          h("ul", { class: "evidence-list" }, ...match.evidence.map((item) => h("li", {}, item))),
        ),
      );
    }

    const statuses = [
      result.baselineStatus !== undefined ? `Normal request: HTTP ${result.baselineStatus}` : null,
      result.provocationStatus !== undefined ? `Test request: HTTP ${result.provocationStatus}` : null,
    ].filter((item): item is string => item !== null);
    if (statuses.length > 0) card.append(h("p", { class: "muted" }, statuses.join("  ·  ")));
    if (result.notes) card.append(h("p", { class: "muted" }, result.notes));
    return card;
  });

  root.append(...cards);
  stagger(cards, 90);
  return root;
}

// ---------- this machine ----------

export function localView(audit: LocalAudit | undefined): HTMLElement {
  const root = h("div");
  if (!audit) {
    root.append(emptyNote("This scan did not audit the local firewall. Use \"Audit this machine\" on the left."));
    return root;
  }

  const state = audit.firewallActive === true ? "on" : audit.firewallActive === false ? "off" : "unknown";
  const text = { on: "Host firewall is active", off: "Host firewall is NOT active", unknown: "Host firewall state unknown" }[state];
  root.append(
    h(
      "div",
      { class: `shield-banner shield-${state}` },
      h("span", { class: "shield-dot" }),
      h("div", {}, h("b", {}, text), h("span", { class: "muted" }, `${audit.platform}${audit.elevated ? "" : " · not elevated, some details may be hidden"}`)),
    ),
  );

  const installed = audit.backends.filter((backend) => backend.state !== "notInstalled");
  const cards = installed.map((backend) => {
    const card = h(
      "article",
      { class: "block" },
      h(
        "header",
        { class: "block-head" },
        h("div", {}, h("h3", {}, backend.name), h("span", { class: "muted" }, backend.detail ?? backend.error ?? "")),
        h("span", { class: `verdict backend-${backend.state}` }, backend.state),
      ),
    );

    const profiles = backend.profiles ?? [];
    if (profiles.length > 0) {
      const row = h("div", { class: "profiles" });
      for (const profile of profiles) {
        row.append(
          h(
            "div",
            { class: `profile ${profile.enabled ? "on" : "off"}` },
            h("b", {}, profile.name),
            h("span", {}, profile.enabled ? "Enabled" : "Disabled"),
            h("span", { class: "muted" }, `Inbound default: ${profile.defaultInbound}`),
          ),
        );
      }
      card.append(row);
    }

    const rules = backend.rules ?? [];
    if (rules.length > 0) {
      const table = h("table", { class: "rules" });
      table.append(h("thead", {}, h("tr", {}, h("th", {}, "Rule"), h("th", {}, "Ports"), h("th", {}, "From"), h("th", {}, "Action"))));
      const tbody = h("tbody");
      for (const rule of rules.slice(0, 60)) {
        tbody.append(
          h("tr", {}, h("td", { class: "break" }, rule.name), h("td", {}, `${rule.localPorts} / ${rule.protocol}`), h("td", {}, rule.remoteAddresses), h("td", {}, rule.action)),
        );
      }
      table.append(tbody);
      const details = h("details", {}, h("summary", {}, `${rules.length} inbound rule${rules.length === 1 ? "" : "s"}`), table);
      if (rules.length > 60) details.append(h("p", { class: "muted" }, `Showing the first 60 of ${rules.length}. Export the report for the full list.`));
      card.append(details);
    }
    return card;
  });

  if (installed.length === 0) root.append(emptyNote("No supported firewall is installed on this machine."));
  root.append(...cards);
  stagger(cards, 90);
  return root;
}

// ---------- history ----------

export function historyView(items: ReportSummary[], currentId: string | null, actions: ViewActions): HTMLElement {
  const root = h("div");
  if (items.length === 0) {
    root.append(emptyNote("No saved scans yet."));
    return root;
  }

  root.append(h("p", { class: "muted pad" }, "Open an earlier scan, or compare one against the scan on screen to see what changed."));
  const rows = items.map((item) => {
    const open = h("button", { class: "ghost small", type: "button" }, "Open");
    open.addEventListener("click", () => actions.openReport(item.id));
    const compare = h("button", { class: "ghost small", type: "button" }, "Compare");
    compare.addEventListener("click", () => actions.compareWith(item.id));
    const isCurrent = item.id === currentId;
    if (isCurrent) {
      open.disabled = true;
      compare.disabled = true;
    }
    return h(
      "div",
      { class: `history-row${isCurrent ? " current" : ""}` },
      h("span", { class: `grade-chip grade-${item.grade}` }, item.grade),
      h("div", { class: "history-main" }, h("b", { class: "break" }, item.label || item.host), h("span", { class: "muted" }, `${formatWhen(item.finishedUtc)} · score ${item.score} · ${item.findings} findings`)),
      isCurrent ? h("span", { class: "muted" }, "on screen") : null,
      open,
      compare,
    );
  });
  root.append(...rows);
  stagger(rows, 35);
  return root;
}

export function driftView(drift: Drift, onClose: () => void): HTMLElement {
  const close = h("button", { class: "ghost small", type: "button" }, "Back to history");
  close.addEventListener("click", onClose);

  const delta = drift.score_after - drift.score_before;
  const trend = delta === 0 ? "unchanged" : delta < 0 ? `down ${-delta}` : `up ${delta}`;
  const root = h(
    "div",
    {},
    h("div", { class: "drift-head" }, h("div", {}, h("h3", {}, "What changed"), h("span", { class: "muted" }, `Risk score ${drift.score_before} → ${drift.score_after} (${trend})`)), close),
  );

  if (!drift.changed) {
    root.append(emptyNote("Nothing changed between these two scans."));
    return root;
  }

  const section = (title: string, rows: HTMLElement[]): void => {
    if (rows.length === 0) return;
    root.append(h("h4", { class: "drift-title" }, title), ...rows);
    stagger(rows, 40);
  };

  const findingRow = (finding: Finding, kind: "new" | "resolved"): HTMLElement =>
    h("div", { class: `drift-row drift-${kind}` }, badge(finding.severity), h("span", { class: "break" }, `${finding.title}${finding.target ? ` (${finding.target})` : ""}`), h("code", {}, finding.id));

  section("New findings", drift.new_findings.map((finding) => findingRow(finding, "new")));
  section("Resolved findings", drift.resolved_findings.map((finding) => findingRow(finding, "resolved")));
  section(
    "Port changes",
    drift.port_changes.map((change) => h("div", { class: "drift-row" }, h("b", {}, `${change.target}:${change.port}`), h("span", {}, `${change.before} → ${change.after}`))),
  );
  section(
    "WAF changes",
    drift.waf_changes.map((change) => h("div", { class: "drift-row" }, h("b", { class: "break" }, change.url), h("span", {}, `${change.before} → ${change.after}`))),
  );
  if (drift.firewall_change) {
    section("Host firewall", [h("div", { class: "drift-row" }, h("b", {}, "Active"), h("span", {}, `${String(drift.firewall_change.before)} → ${String(drift.firewall_change.after)}`))]);
  }
  return root;
}
