// Small DOM helpers. Everything is built with createElement/textContent, never innerHTML,
// because report data (headers, rule names, URLs) comes from scanned systems and is untrusted.

type Child = Node | string | null | undefined | false;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Record<string, string | boolean | undefined> = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (name === "class") element.className = String(value);
    else if (value === true) element.setAttribute(name, "");
    else element.setAttribute(name, value);
  }
  append(element, ...children);
  return element;
}

export function append(parent: Element, ...children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(child);
  }
}

export function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) throw new Error(`Missing element #${id}`);
  return element as T;
}

export function clear(element: Element): void {
  element.replaceChildren();
}

export const reducedMotion = (): boolean => window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Counts a number up to its target so values land with a little weight. */
export function countUp(element: HTMLElement, target: number, durationMs = 900): void {
  if (reducedMotion()) {
    element.textContent = String(target);
    return;
  }
  const start = performance.now();
  const from = Number(element.textContent) || 0;
  const tick = (now: number): void => {
    const t = Math.min(1, (now - start) / durationMs);
    const eased = 1 - Math.pow(1 - t, 3);
    element.textContent = String(Math.round(from + (target - from) * eased));
    if (t < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

/** Gives a list of freshly added elements a staggered entrance. */
export function stagger(elements: Iterable<HTMLElement>, stepMs = 45): void {
  let index = 0;
  for (const element of elements) {
    element.classList.add("rise");
    element.style.animationDelay = `${Math.min(index * stepMs, 600)}ms`;
    index += 1;
  }
}

let toastTimer: number | undefined;

export function toast(message: string, kind: "info" | "error" = "info"): void {
  const element = byId("toast");
  element.textContent = message;
  element.className = `toast ${kind} show`;
  element.hidden = false;
  window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    element.classList.remove("show");
  }, 4200);
}

export function formatWhen(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}
