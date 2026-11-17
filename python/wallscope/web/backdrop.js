import { reducedMotion } from "./dom.js";
const LINK_DISTANCE = 150;
export function startBackdrop(canvas) {
    const context = canvas.getContext("2d");
    if (!context)
        return;
    const ctx = context;
    let width = 0;
    let height = 0;
    let nodes = [];
    const pointer = { x: 0.5, y: 0.5, tx: 0.5, ty: 0.5 };
    const resize = () => {
        const ratio = Math.min(window.devicePixelRatio || 1, 2);
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = Math.floor(width * ratio);
        canvas.height = Math.floor(height * ratio);
        ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
        const count = Math.max(28, Math.min(90, Math.floor((width * height) / 22000)));
        nodes = Array.from({ length: count }, () => {
            const z = 0.25 + Math.random() * 0.75;
            return {
                x: Math.random() * width,
                y: Math.random() * height,
                z,
                vx: (Math.random() - 0.5) * 0.28 * z,
                vy: (Math.random() - 0.5) * 0.28 * z,
                pulse: Math.random() * Math.PI * 2,
            };
        });
    };
    const draw = (animate) => {
        ctx.clearRect(0, 0, width, height);
        pointer.x += (pointer.tx - pointer.x) * 0.045;
        pointer.y += (pointer.ty - pointer.y) * 0.045;
        const projected = nodes.map((node) => {
            if (animate) {
                node.x += node.vx;
                node.y += node.vy;
                node.pulse += 0.012 + node.z * 0.01;
                if (node.x < -40)
                    node.x = width + 40;
                if (node.x > width + 40)
                    node.x = -40;
                if (node.y < -40)
                    node.y = height + 40;
                if (node.y > height + 40)
                    node.y = -40;
            }
            return {
                x: node.x + (pointer.x - 0.5) * -70 * node.z,
                y: node.y + (pointer.y - 0.5) * -50 * node.z,
                z: node.z,
                glow: 0.5 + Math.sin(node.pulse) * 0.5,
            };
        });
        for (let i = 0; i < projected.length; i += 1) {
            const a = projected[i];
            if (!a)
                continue;
            for (let j = i + 1; j < projected.length; j += 1) {
                const b = projected[j];
                if (!b || Math.abs(a.z - b.z) > 0.3)
                    continue;
                const distance = Math.hypot(a.x - b.x, a.y - b.y);
                if (distance > LINK_DISTANCE)
                    continue;
                const alpha = (1 - distance / LINK_DISTANCE) * 0.22 * Math.min(a.z, b.z);
                ctx.strokeStyle = `rgba(110, 170, 240, ${alpha.toFixed(3)})`;
                ctx.lineWidth = Math.min(a.z, b.z);
                ctx.beginPath();
                ctx.moveTo(a.x, a.y);
                ctx.lineTo(b.x, b.y);
                ctx.stroke();
            }
        }
        for (const node of projected) {
            const radius = 0.8 + node.z * 2.1;
            ctx.fillStyle = `rgba(142, 197, 255, ${(0.18 + node.z * 0.5 * (0.6 + node.glow * 0.4)).toFixed(3)})`;
            ctx.beginPath();
            ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
            ctx.fill();
        }
    };
    resize();
    window.addEventListener("resize", resize);
    window.addEventListener("pointermove", (event) => {
        pointer.tx = event.clientX / Math.max(width, 1);
        pointer.ty = event.clientY / Math.max(height, 1);
    });
    if (reducedMotion()) {
        draw(false);
        return;
    }
    let running = true;
    document.addEventListener("visibilitychange", () => {
        const visible = document.visibilityState === "visible";
        if (visible && !running) {
            running = true;
            requestAnimationFrame(loop);
        }
        else if (!visible) {
            running = false;
        }
    });
    const loop = () => {
        if (!running)
            return;
        draw(true);
        requestAnimationFrame(loop);
    };
    requestAnimationFrame(loop);
}
