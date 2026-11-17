// WallScope dashboard entry point. By ZaKari Perry.

import { api, ApiError, SEVERITIES, type Mood, type ScanRequest, type StoredReport } from "./api.js";
import { startBackdrop } from "./backdrop.js";
import { byId, clear, countUp, h, reducedMotion, stagger, toast } from "./dom.js";
import { Scout } from "./scout.js";
import { driftView, findingsView, historyView, localView, networkView, webView, type ViewActions } from "./views.js";

type Tab = "findings" | "network" | "web" | "local" | "history";

const GAUGE_LENGTH = 2 * Math.PI * 50;
const SCAN_STEPS = ["Starting the engine", "Reading firewall state", "Sending probes", "Comparing responses", "Scoring findings"];

let current: StoredReport | null = null;
let activeTab: Tab = "findings";
let setupMode = false;
let scout: Scout;

// ---------- sign-in ----------

function showAuth(setup: boolean): void {
  setupMode = setup;
  byId("console").hidden = true;
  byId("auth").hidden = false;
  byId("auth-title").textContent = setup ? "Create your operator account" : "Sign in";
  byId("auth-sub").textContent = setup
    ? "First run on this computer. Pick a username and a password of at least 10 characters."
    : "Use your operator account.";
  byId("auth-submit").textContent = setup ? "Create account" : "Sign in";
  byId("confirm-row").hidden = !setup;
  byId<HTMLInputElement>("password").autocomplete = setup ? "new-password" : "current-password";
  byId<HTMLInputElement>("username").focus();
}

function authError(message: string | null): void {
  const element = byId("auth-error");
  element.hidden = message === null;
  element.textContent = message ?? "";
  if (message) {
    const card = document.querySelector(".auth-card");
    card?.classList.remove("shake");
    void (card as HTMLElement | null)?.offsetWidth;
    card?.classList.add("shake");
  }
}

async function submitAuth(event: Event): Promise<void> {
  event.preventDefault();
  const username = byId<HTMLInputElement>("username").value.trim();
  const password = byId<HTMLInputElement>("password").value;
  const button = byId<HTMLButtonElement>("auth-submit");
  authError(null);

  if (!username || !password) return authError("Enter a username and password.");
  if (setupMode) {
    if (password.length < 10) return authError("Password must be at least 10 characters.");
    if (password !== byId<HTMLInputElement>("confirm").value) return authError("The two passwords don't match.");
  }

  button.disabled = true;
  button.classList.add("loading");
  try {
    const result = setupMode ? await api.setup(username, password) : await api.login(username, password);
    byId<HTMLInputElement>("password").value = "";
    byId<HTMLInputElement>("confirm").value = "";
    await enterConsole(result.user);
  } catch (error) {
    authError(error instanceof ApiError ? error.message : "Sign-in failed.");
  } finally {
    button.disabled = false;
    button.classList.remove("loading");
  }
}

// ---------- console ----------

async function enterConsole(user: string): Promise<void> {
  byId("auth").hidden = true;
  const consoleElement = byId("console");
  consoleElement.hidden = false;
  consoleElement.classList.add("enter");
  byId("who").textContent = user;
  scout.greet(user);

  try {
    const status = await api.status();
    const engine = byId("pill-engine");
    engine.textContent = status.engine ? "Engine ready" : "Engine not built";
    engine.className = `pill ${status.engine ? "ok" : "warn"}`;
    engine.title = status.engine ?? "Run 'dotnet build -c Release' in the project folder, then restart the dashboard.";
    const assistantPill = byId("pill-assistant");
    assistantPill.textContent = status.assistant === "claude" ? "Scout: Claude" : "Scout: built-in";
    assistantPill.className = "pill ok";
    scout.setAssistantMode(status.assistant);
  } catch (error) {
    handleError(error);
  }
}

function handleError(error: unknown): void {
  if (error instanceof ApiError && error.status === 401) {
    current = null;
    showAuth(false);
    authError("Your session ended. Sign in again.");
    return;
  }
  toast(error instanceof ApiError ? error.message : "Something went wrong.", "error");
}

function moodFor(report: StoredReport): Mood {
  const counts = report.risk.counts;
  if (counts.critical > 0 || counts.high > 0) return "alert";
  return counts.medium > 0 ? "neutral" : "happy";
}

function showReport(stored: StoredReport, announce: boolean): void {
  current = stored;
  byId("empty").hidden = true;
  const results = byId("results");
  results.hidden = false;

  // Gauge: the arc sweeps to the score and takes the colour of the grade.
  const arc = byId("gauge-arc") as unknown as SVGCircleElement;
  arc.style.strokeDasharray = String(GAUGE_LENGTH);
  arc.style.strokeDashoffset = String(GAUGE_LENGTH);
  arc.setAttribute("class", `gauge-arc grade-stroke-${stored.risk.grade}`);
  requestAnimationFrame(() =>
    requestAnimationFrame(() => {
      arc.style.strokeDashoffset = String(GAUGE_LENGTH * (1 - stored.risk.score / 100));
    }),
  );
  byId("score").textContent = "0";
  countUp(byId("score"), stored.risk.score);
  const grade = byId("grade");
  grade.textContent = stored.risk.grade;
  grade.className = `grade grade-${stored.risk.grade}`;
  byId("posture").textContent = stored.risk.posture;
  byId("report-label").textContent = stored.label ? `${stored.label} · ${stored.report.host}` : stored.report.host;

  const tiles = byId("tiles");
  clear(tiles);
  const tileElements = SEVERITIES.map((severity) => {
    const value = h("b", {}, "0");
    countUp(value, stored.risk.counts[severity] ?? 0, 700);
    return h("div", { class: `tile sev-edge-${severity}` }, value, h("span", {}, severity));
  });
  tiles.append(...tileElements);
  stagger(tileElements, 60);

  for (const format of ["html", "md", "sarif", "json"] as const) {
    byId<HTMLAnchorElement>(`export-${format}`).href = api.exportUrl(stored.id, format);
  }

  // A fresh scan always lands on its findings; reopening a saved one keeps the tab you were on.
  void selectTab(announce || activeTab === "history" ? "findings" : activeTab);

  if (announce) {
    const { score, grade: letter, counts } = stored.risk;
    const urgent = counts.critical + counts.high;
    const line =
      urgent > 0
        ? `Scan done. Risk score ${score}, grade ${letter}. ${urgent} item${urgent === 1 ? " needs" : "s need"} attention soon. Want the fix order?`
        : `Scan done. Risk score ${score}, grade ${letter}. Nothing urgent. Ask me for a summary if you want the details.`;
    scout.setReport(stored.id, moodFor(stored), line);
  } else {
    scout.setReport(stored.id, moodFor(stored));
  }
}

const actions: ViewActions = {
  askScout: (question) => void scout.ask(question),
  openReport: (id) => void openReport(id),
  compareWith: (id) => void compare(id),
};

async function selectTab(tab: Tab): Promise<void> {
  activeTab = tab;
  for (const button of document.querySelectorAll<HTMLButtonElement>(".tab")) {
    const selected = button.dataset["tab"] === tab;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-selected", String(selected));
  }

  const body = byId("tab-body");
  if (!current) return;
  let view: HTMLElement;
  try {
    switch (tab) {
      case "findings":
        view = findingsView(current.report.findings, actions);
        break;
      case "network":
        view = networkView(current.report.networkProbes ?? []);
        break;
      case "web":
        view = webView(current.report.wafResults ?? []);
        break;
      case "local":
        view = localView(current.report.localAudit);
        break;
      case "history":
        view = historyView(await api.reports(), current.id, actions);
        break;
    }
  } catch (error) {
    return handleError(error);
  }
  body.classList.remove("swap");
  void body.offsetWidth;
  body.classList.add("swap");
  body.replaceChildren(view);
}

async function openReport(id: string): Promise<void> {
  try {
    showReport(await api.report(id), false);
    toast("Opened saved scan.");
  } catch (error) {
    handleError(error);
  }
}

async function compare(baseId: string): Promise<void> {
  if (!current) return;
  try {
    const drift = await api.diff(baseId, current.id);
    byId("tab-body").replaceChildren(driftView(drift, () => void selectTab("history")));
  } catch (error) {
    handleError(error);
  }
}

// ---------- scans ----------

function list(id: string): string[] {
  return byId<HTMLInputElement>(id)
    .value.split(/[\s,]+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function isLocalTarget(value: string): boolean {
  let host = value;
  try {
    if (/^https?:\/\//i.test(value)) host = new URL(value).hostname;
  } catch {
    return false;
  }
  host = host.replace(/^\[|\]$/g, "").toLowerCase();
  return host === "localhost" || host.endsWith(".localhost") || host === "::1" || /^127(\.\d{1,3}){3}$/.test(host);
}

async function runScan(title: string, request: ScanRequest, trigger: HTMLButtonElement): Promise<void> {
  const remote = [...(request.targets ?? []), ...(request.urls ?? [])].filter((item) => !isLocalTarget(item));
  request.authorized = byId<HTMLInputElement>("authorized").checked;
  if (remote.length > 0 && !request.authorized) {
    const box = document.querySelector<HTMLElement>(".authorize");
    box?.classList.remove("nudge");
    void box?.offsetWidth;
    box?.classList.add("nudge");
    toast("Tick the permission box first. Only scan systems you own or are allowed to test.", "error");
    return;
  }

  const overlay = byId("scanning");
  byId("scanning-title").textContent = title;
  const step = byId("scanning-step");
  let index = 0;
  step.textContent = SCAN_STEPS[0] ?? "";
  const ticker = window.setInterval(() => {
    index = Math.min(index + 1, SCAN_STEPS.length - 1);
    step.textContent = SCAN_STEPS[index] ?? "";
  }, 1400);
  overlay.hidden = false;
  trigger.disabled = true;

  try {
    showReport(await api.scan(request), true);
  } catch (error) {
    handleError(error);
  } finally {
    window.clearInterval(ticker);
    overlay.hidden = true;
    trigger.disabled = false;
  }
}

/** Material-style ripple so every button press has a visible response. */
function ripple(event: PointerEvent): void {
  const button = (event.target as HTMLElement).closest<HTMLElement>("button.primary, button.secondary");
  if (!button || reducedMotion()) return;
  const box = button.getBoundingClientRect();
  const dot = h("span", { class: "ripple" });
  const size = Math.max(box.width, box.height) * 2;
  dot.style.width = dot.style.height = `${size}px`;
  dot.style.left = `${event.clientX - box.left - size / 2}px`;
  dot.style.top = `${event.clientY - box.top - size / 2}px`;
  button.append(dot);
  dot.addEventListener("animationend", () => dot.remove());
}

function wire(): void {
  byId("auth-form").addEventListener("submit", (event) => void submitAuth(event));
  byId("toggle-password").addEventListener("click", () => {
    const input = byId<HTMLInputElement>("password");
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    byId("toggle-password").textContent = show ? "Hide" : "Show";
  });

  byId("signout").addEventListener("click", async () => {
    try {
      await api.logout();
    } catch {
      // Signing out locally is enough even if the server is unreachable.
    }
    current = null;
    byId("results").hidden = true;
    byId("empty").hidden = false;
    showAuth(false);
  });

  byId<HTMLButtonElement>("run-local").addEventListener("click", (event) =>
    void runScan("Auditing this machine", { local: true }, event.currentTarget as HTMLButtonElement),
  );

  byId<HTMLButtonElement>("run-probe").addEventListener("click", (event) => {
    const targets = list("targets");
    if (targets.length === 0) return toast("Enter a host or IP address to probe.", "error");
    void runScan(`Probing ${targets.join(", ")}`, { targets, ports: byId<HTMLInputElement>("ports").value.trim() || "top" }, event.currentTarget as HTMLButtonElement);
  });

  byId<HTMLButtonElement>("run-waf").addEventListener("click", (event) => {
    const urls = list("urls");
    if (urls.length === 0) return toast("Enter a website URL to check.", "error");
    void runScan(`Checking ${urls.join(", ")}`, { urls, passive: byId<HTMLInputElement>("passive").checked }, event.currentTarget as HTMLButtonElement);
  });

  byId<HTMLButtonElement>("run-all").addEventListener("click", (event) =>
    void runScan(
      "Running everything",
      {
        local: true,
        targets: list("targets"),
        ports: byId<HTMLInputElement>("ports").value.trim() || "top",
        urls: list("urls"),
        passive: byId<HTMLInputElement>("passive").checked,
      },
      event.currentTarget as HTMLButtonElement,
    ),
  );

  byId("load-sample").addEventListener("click", async () => {
    try {
      showReport(await api.sample(), true);
      toast("Sample data loaded. These results are examples, not a real scan.");
    } catch (error) {
      handleError(error);
    }
  });

  for (const button of document.querySelectorAll<HTMLButtonElement>(".tab")) {
    button.addEventListener("click", () => void selectTab(button.dataset["tab"] as Tab));
  }

  document.addEventListener("pointerdown", ripple);
}

async function boot(): Promise<void> {
  startBackdrop(byId<HTMLCanvasElement>("backdrop"));
  scout = new Scout();
  wire();
  try {
    const session = await api.session();
    if (session.authenticated && session.user) await enterConsole(session.user);
    else showAuth(session.setupRequired);
  } catch (error) {
    showAuth(false);
    authError(error instanceof ApiError ? error.message : "Can't reach the server.");
  }
}

void boot();
