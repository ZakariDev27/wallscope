import { api, ApiError } from "./api.js";
import { byId, clear, h, reducedMotion } from "./dom.js";
const SVG = "http://www.w3.org/2000/svg";
function svg(tag, attrs) {
    const element = document.createElementNS(SVG, tag);
    for (const [name, value] of Object.entries(attrs))
        element.setAttribute(name, value);
    return element;
}
class Avatar {
    root;
    head;
    pupils = [];
    mood = "neutral";
    constructor(root) {
        this.root = root;
        const canvas = svg("svg", { viewBox: "0 0 120 120", class: "scout-svg" });
        const ring = svg("circle", { cx: "60", cy: "62", r: "52", class: "scout-ring" });
        const halo = svg("circle", { cx: "60", cy: "62", r: "44", class: "scout-halo" });
        const shadow = svg("ellipse", { cx: "60", cy: "112", rx: "24", ry: "4", class: "scout-shadow" });
        this.head = svg("g", { class: "scout-head-group" });
        const antenna = svg("line", { x1: "60", y1: "30", x2: "60", y2: "17", class: "scout-antenna" });
        const beacon = svg("circle", { cx: "60", cy: "14", r: "4.5", class: "scout-beacon" });
        const shell = svg("rect", { x: "24", y: "30", width: "72", height: "62", rx: "22", class: "scout-shell" });
        const visor = svg("rect", { x: "32", y: "42", width: "56", height: "30", rx: "15", class: "scout-visor" });
        const earLeft = svg("rect", { x: "17", y: "52", width: "8", height: "18", rx: "4", class: "scout-ear" });
        const earRight = svg("rect", { x: "95", y: "52", width: "8", height: "18", rx: "4", class: "scout-ear" });
        const mouth = svg("path", { d: "M50 82 Q60 86 70 82", class: "scout-mouth" });
        this.head.append(antenna, beacon, earLeft, earRight, shell, visor);
        for (const cx of [47, 73]) {
            const eye = svg("g", { class: "scout-eye" });
            eye.append(svg("ellipse", { cx: String(cx), cy: "57", rx: "7.5", ry: "8.5", class: "scout-eye-white" }));
            const pupil = svg("circle", { cx: String(cx), cy: "57", r: "3.6", class: "scout-pupil" });
            eye.append(pupil);
            this.pupils.push(pupil);
            this.head.append(eye);
        }
        this.head.append(mouth);
        canvas.append(ring, halo, shadow, this.head);
        root.append(canvas);
        this.setMood("neutral");
        if (!reducedMotion()) {
            window.addEventListener("pointermove", (event) => this.lookAt(event.clientX, event.clientY));
            this.scheduleBlink();
        }
    }
    setMood(mood) {
        this.mood = mood;
        this.root.dataset["mood"] = mood;
    }
    getMood() {
        return this.mood;
    }
    setTalking(talking) {
        this.root.classList.toggle("talking", talking);
    }
    hop() {
        this.root.classList.remove("hop");
        void this.root.offsetWidth;
        this.root.classList.add("hop");
    }
    lookAt(x, y) {
        const box = this.root.getBoundingClientRect();
        const dx = x - (box.left + box.width / 2);
        const dy = y - (box.top + box.height / 2);
        const distance = Math.hypot(dx, dy) || 1;
        const reach = Math.min(1, distance / 320);
        const ux = (dx / distance) * reach;
        const uy = (dy / distance) * reach;
        for (const pupil of this.pupils) {
            pupil.style.transform = `translate(${(ux * 3.2).toFixed(2)}px, ${(uy * 3.6).toFixed(2)}px)`;
        }
        this.head.style.transform = `translate(${(ux * 2.4).toFixed(2)}px, ${(uy * 1.8).toFixed(2)}px) rotate(${(ux * 5).toFixed(2)}deg)`;
    }
    scheduleBlink() {
        window.setTimeout(() => {
            this.root.classList.add("blink");
            window.setTimeout(() => this.root.classList.remove("blink"), 150);
            this.scheduleBlink();
        }, 2200 + Math.random() * 3800);
    }
}
export class Scout {
    avatar;
    log = byId("chat-log");
    suggestions = byId("chat-suggestions");
    status = byId("scout-status");
    input = byId("chat-input");
    history = [];
    reportId = null;
    busy = false;
    constructor() {
        this.avatar = new Avatar(byId("scout-avatar"));
        byId("chat-form").addEventListener("submit", (event) => {
            event.preventDefault();
            const text = this.input.value.trim();
            if (text)
                void this.ask(text);
        });
    }
    greet(user) {
        clear(this.log);
        this.history.length = 0;
        void this.say(`Hi ${user}, I'm Scout. Run a scan and I'll explain what it finds and what to fix first.`, "happy");
        this.setSuggestions(["What can you do?", "What is a WAF?", "What does filtered mean?"]);
    }
    setReport(reportId, mood, announce) {
        this.reportId = reportId;
        this.avatar.setMood(mood);
        if (announce) {
            this.avatar.hop();
            void this.say(announce, mood);
            this.setSuggestions(["Summarize my scan", "What should I fix first?", "Which ports are open?", "Explain my risk score"]);
        }
    }
    setAssistantMode(mode) {
        this.status.textContent = mode === "claude" ? "Powered by Claude" : "Built-in knowledge";
    }
    async ask(text) {
        if (this.busy)
            return;
        this.busy = true;
        this.input.value = "";
        this.addBubble("user", text);
        this.history.push({ role: "user", content: text });
        this.setSuggestions([]);
        const previousMood = this.avatar.getMood();
        this.avatar.setMood("thinking");
        const typing = h("div", { class: "bubble assistant typing" }, h("span"), h("span"), h("span"));
        this.log.append(typing);
        this.scrollDown();
        try {
            const reply = await api.chat(text, this.reportId, this.history.slice(0, -1));
            typing.remove();
            await this.say(reply.text, reply.mood === "thinking" ? previousMood : reply.mood);
            this.setSuggestions(reply.suggestions);
        }
        catch (error) {
            typing.remove();
            const message = error instanceof ApiError ? error.message : "Something went wrong.";
            await this.say(`I couldn't answer that: ${message}`, previousMood);
        }
        finally {
            this.busy = false;
            this.input.focus();
        }
    }
    async say(text, mood) {
        this.avatar.setMood(mood);
        this.history.push({ role: "assistant", content: text });
        const bubble = this.addBubble("assistant", "");
        if (reducedMotion()) {
            bubble.textContent = text;
            this.scrollDown();
            return;
        }
        this.avatar.setTalking(true);
        const step = Math.max(2, Math.ceil(text.length / 140));
        for (let i = 0; i < text.length; i += step) {
            bubble.textContent = text.slice(0, i + step);
            this.scrollDown();
            await new Promise((resolve) => window.setTimeout(resolve, 14));
        }
        bubble.textContent = text;
        this.avatar.setTalking(false);
    }
    addBubble(role, text) {
        const bubble = h("div", { class: `bubble ${role}` }, text);
        this.log.append(bubble);
        this.scrollDown();
        return bubble;
    }
    setSuggestions(items) {
        clear(this.suggestions);
        items.slice(0, 4).forEach((item, index) => {
            const chip = h("button", { class: "chip rise", type: "button" }, item);
            chip.style.animationDelay = `${index * 60}ms`;
            chip.addEventListener("click", () => void this.ask(item));
            this.suggestions.append(chip);
        });
    }
    scrollDown() {
        this.log.scrollTop = this.log.scrollHeight;
    }
}
