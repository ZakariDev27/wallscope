export function h(tag, attrs = {}, ...children) {
    const element = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs)) {
        if (value === undefined || value === false)
            continue;
        if (name === "class")
            element.className = String(value);
        else if (value === true)
            element.setAttribute(name, "");
        else
            element.setAttribute(name, value);
    }
    append(element, ...children);
    return element;
}
export function append(parent, ...children) {
    for (const child of children) {
        if (child === null || child === undefined || child === false)
            continue;
        parent.append(child);
    }
}
export function byId(id) {
    const element = document.getElementById(id);
    if (!element)
        throw new Error(`Missing element #${id}`);
    return element;
}
export function clear(element) {
    element.replaceChildren();
}
export const reducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
export function countUp(element, target, durationMs = 900) {
    if (reducedMotion()) {
        element.textContent = String(target);
        return;
    }
    const start = performance.now();
    const from = Number(element.textContent) || 0;
    const tick = (now) => {
        const t = Math.min(1, (now - start) / durationMs);
        const eased = 1 - Math.pow(1 - t, 3);
        element.textContent = String(Math.round(from + (target - from) * eased));
        if (t < 1)
            requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
}
export function stagger(elements, stepMs = 45) {
    let index = 0;
    for (const element of elements) {
        element.classList.add("rise");
        element.style.animationDelay = `${Math.min(index * stepMs, 600)}ms`;
        index += 1;
    }
}
let toastTimer;
export function toast(message, kind = "info") {
    const element = byId("toast");
    element.textContent = message;
    element.className = `toast ${kind} show`;
    element.hidden = false;
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => {
        element.classList.remove("show");
    }, 4200);
}
export function formatWhen(iso) {
    const date = new Date(iso);
    return Number.isNaN(date.getTime()) ? iso : date.toLocaleString();
}
