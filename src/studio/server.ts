import http from "node:http";
import net from "node:net";
import { promises, existsSync } from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { StudioController } from "./controller";
import { LogEntry } from "./logbus";

const UI_PORT = 63000;

const MIME: Record<string, string> = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".json": "application/json; charset=utf-8",
    ".gif": "image/gif",
    ".ico": "image/x-icon",
    ".wasm": "application/wasm",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".map": "application/json; charset=utf-8",
};

function json(res: http.ServerResponse, status: number, body: unknown) {
    const data = JSON.stringify(body);
    res.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Length": Buffer.byteLength(data),
    });
    res.end(data);
}

async function readBody(req: http.IncomingMessage): Promise<any> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    if (chunks.length === 0) return {};
    try {
        return JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
        return {};
    }
}

function openExternal(url: string, extraArgs: string[] = []) {
    const candidates = [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
    ];
    for (const exe of candidates) {
        try {
            const child = spawn(exe, [...extraArgs, url], { detached: true, stdio: "ignore" });
            child.unref();
            return true;
        } catch {
            /* try next */
        }
    }
    try {
        const child = spawn("cmd", ["/c", "start", "", url], { detached: true, stdio: "ignore", windowsVerbatimArguments: true });
        child.unref();
        return true;
    } catch {
        return false;
    }
}

function isPortOpen(port: number): Promise<boolean> {
    return new Promise((resolve) => {
        const socket = net.connect({ port, host: "127.0.0.1" });
        socket.setTimeout(400);
        socket.once("connect", () => {
            socket.destroy();
            resolve(true);
        });
        socket.once("timeout", () => {
            socket.destroy();
            resolve(false);
        });
        socket.once("error", () => {
            socket.destroy();
            resolve(false);
        });
    });
}

/**
 * 内置 Chromium（2021 版）是唯一还允许 devtools:// 页面连外部 ws 的宿主。
 * 命令行直接传 devtools:// 会被降级，必须先起远程调试端口，再用 PUT /json/new 建标签页。
 */
async function openBundledDevtools(chromium: string, profile: string, port: number, target: string) {
    if (!(await isPortOpen(port))) {
        const child = spawn(
            chromium,
            [
                "--user-data-dir=" + profile,
                "--no-first-run",
                "--no-default-browser-check",
                "--remote-debugging-port=" + port,
                "about:blank",
            ],
            { detached: true, stdio: "ignore" },
        );
        child.unref();

        let ready = false;
        for (let i = 0; i < 40; i++) {
            await new Promise((resolve) => setTimeout(resolve, 250));
            if (await isPortOpen(port)) {
                ready = true;
                break;
            }
        }
        if (!ready) throw new Error("内置 Chromium 启动超时（10s）");
    }

    const url = `devtools://devtools/bundled/inspector.html?ws=${target}`;
    const response = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(url)}`, {
        method: "PUT",
    });
    if (!response.ok) {
        throw new Error(`创建 DevTools 页失败: HTTP ${response.status}`);
    }
    return url;
}

export function createStudioServer(controller: StudioController) {
    const sseClients = new Set<http.ServerResponse>();

    controller.logs.on("entry", (entry: LogEntry) => {
        const payload = `data: ${JSON.stringify(entry)}\n\n`;
        for (const client of sseClients) {
            try {
                client.write(payload);
            } catch {
                sseClients.delete(client);
            }
        }
    });

    controller.on("status", (status) => {
        const payload = `event: status\ndata: ${JSON.stringify(status)}\n\n`;
        for (const client of sseClients) {
            try {
                client.write(payload);
            } catch {
                sseClients.delete(client);
            }
        }
    });

    const server = http.createServer(async (req, res) => {
        const url = new URL(req.url ?? "/", `http://127.0.0.1:${UI_PORT}`);
        const pathname = url.pathname;

        try {
            if (pathname === "/api/status") {
                return json(res, 200, controller.status());
            }

            if (pathname === "/api/start" && req.method === "POST") {
                const body = await readBody(req);
                const status = await controller.start({ autoDetect: body?.autoDetect === true });
                return json(res, 200, status);
            }

            if (pathname === "/api/stop" && req.method === "POST") {
                const status = await controller.stop();
                return json(res, 200, status);
            }

            if (pathname === "/api/logs") {
                return json(res, 200, controller.logs.snapshot());
            }

            if (pathname === "/api/logs/stream") {
                res.writeHead(200, {
                    "Content-Type": "text/event-stream; charset=utf-8",
                    "Cache-Control": "no-cache, no-transform",
                    Connection: "keep-alive",
                    "X-Accel-Buffering": "no",
                });
                res.write(`: connected\n\n`);
                for (const entry of controller.logs.snapshot()) {
                    res.write(`data: ${JSON.stringify(entry)}\n\n`);
                }
                sseClients.add(res);
                req.on("close", () => sseClients.delete(res));
                return;
            }

            if (pathname === "/api/eval" && req.method === "POST") {
                const body = await readBody(req);
                const expression = String(body?.expression ?? "").trim();
                if (!expression) return json(res, 400, { ok: false, error: "表达式为空" });
                if (controller.status().state !== "ready") {
                    return json(res, 409, { ok: false, error: "调试尚未就绪" });
                }
                const result = await controller.evaluate(expression);
                return json(res, 200, result);
            }

            if (pathname === "/api/open-devtools" && req.method === "POST") {
                const status = controller.status();
                if (status.state !== "ready") {
                    return json(res, 409, { ok: false, error: "调试尚未就绪" });
                }

                // 优先用随包附带的 Chromium（2021 版）：它允许命令行打开 devtools://，
                // 且自带的前端与 WMPF 的 V8 inspector 兼容。Chrome 157 已禁止这条路。
                const bundledChromium = path.join(projectRoot(), "chromium", "chrome.exe");
                if (existsSync(bundledChromium)) {
                    const profile = path.join(projectRoot(), "chromium-profile");
                    try {
                        const url = await openBundledDevtools(
                            bundledChromium,
                            profile,
                            9238,
                            `127.0.0.1:${status.cdpPort}`,
                        );
                        return json(res, 200, { ok: true, mode: "bundled-chromium", url });
                    } catch (e) {
                        return json(res, 500, { ok: false, error: e instanceof Error ? e.message : String(e) });
                    }
                }

                // 没有自带 Chromium 时，只能提示用户手动进 chrome://inspect
                return json(res, 200, {
                    ok: false,
                    mode: "manual",
                    inspectUrl: "chrome://inspect",
                    target: `127.0.0.1:${status.cdpPort}`,
                });
            }

            if (pathname === "/api/open-browser" && req.method === "POST") {
                const ok = openExternal(`http://127.0.0.1:${UI_PORT}/`);
                return json(res, 200, { ok });
            }

            // 静态文件
            const file = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
            const webRoot = path.join(projectRoot(), "web");
            const full = path.join(webRoot, file);
            const normalized = path.resolve(full);
            if (!normalized.startsWith(path.resolve(webRoot))) {
                return json(res, 403, { error: "forbidden" });
            }
            const data = await promises.readFile(normalized);
            res.writeHead(200, {
                "Content-Type": MIME[path.extname(normalized)] ?? "application/octet-stream",
                "Cache-Control": "no-store",
            });
            res.end(data);
            return;
        } catch (e) {
            if ((e as NodeJS.ErrnoException).code === "ENOENT") {
                res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
                res.end("not found");
                return;
            }
            json(res, 500, { error: e instanceof Error ? e.message : String(e) });
        }
    });

    return {
        server,
        listen: () =>
            new Promise<void>((resolve, reject) => {
                server.once("error", reject);
                server.listen(UI_PORT, "127.0.0.1", () => resolve());
            }),
    };
}

function projectRoot(): string {
    if ((process as unknown as { pkg?: string }).pkg) {
        return path.dirname(process.execPath);
    }
    if (existsSync(path.join(__dirname, "web"))) {
        return __dirname;
    }
    return path.resolve(__dirname, "..", "..");
}

export { UI_PORT };
