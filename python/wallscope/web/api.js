export const SEVERITIES = ["critical", "high", "medium", "low", "info"];
export class ApiError extends Error {
    status;
    constructor(message, status) {
        super(message);
        this.status = status;
    }
}
async function call(method, path, body) {
    const init = { method, credentials: "same-origin" };
    if (method === "POST") {
        init.headers = { "Content-Type": "application/json", "X-WallScope": "1" };
        init.body = JSON.stringify(body ?? {});
    }
    let response;
    try {
        response = await fetch(path, init);
    }
    catch {
        throw new ApiError("Can't reach the WallScope server. Is it still running?", 0);
    }
    let payload = null;
    try {
        payload = await response.json();
    }
    catch {
    }
    if (!response.ok) {
        const message = payload && typeof payload === "object" && "error" in payload
            ? String(payload.error)
            : `Request failed (${response.status}).`;
        throw new ApiError(message, response.status);
    }
    return payload;
}
export const api = {
    session: () => call("GET", "/api/session"),
    setup: (username, password) => call("POST", "/api/setup", { username, password }),
    login: (username, password) => call("POST", "/api/login", { username, password }),
    logout: () => call("POST", "/api/logout"),
    status: () => call("GET", "/api/status"),
    scan: (request) => call("POST", "/api/scan", request),
    sample: () => call("POST", "/api/sample"),
    reports: () => call("GET", "/api/reports"),
    report: (id) => call("GET", `/api/reports/${encodeURIComponent(id)}`),
    diff: (base, head) => call("POST", "/api/diff", { base, head }),
    chat: (message, reportId, history) => call("POST", "/api/chat", { message, reportId, history }),
    exportUrl: (id, format) => `/api/reports/${encodeURIComponent(id)}/export?format=${format}`,
};
