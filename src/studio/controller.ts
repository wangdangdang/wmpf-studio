import path from "node:path";
import http from "node:http";
import { existsSync } from "node:fs";
import { spawn, execFileSync, ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import WebSocket, { WebSocketServer } from "ws";

import { LogBus } from "./logbus";

const thirdPartyDir = existsSync(path.join(__dirname, "third-party"))
    ? path.join(__dirname, "third-party")
    : path.resolve(__dirname, "..", "third-party");
const codex = require(path.join(thirdPartyDir, "RemoteDebugCodex.js"));
const messageProto = require(path.join(thirdPartyDir, "WARemoteDebugProtobuf.js"));

export type StudioState = "idle" | "starting" | "ready" | "error";

export type StudioStatus = {
    state: StudioState;
    version: number | null;
    pid: number | null;
    debugPort: number;
    cdpPort: number;
    cdpUrl: string;
    devtoolsUrl: string;
    configSource: "file" | "auto-detect" | "none";
    error: string | null;
    startedAt: number | null;
    clients: { cdp: number; miniapp: number };
};

type AgentHello = { event: "hello"; pid: number; version: number };
type AgentConfig = { event: "config"; source: "file" | "auto"; config: unknown };

const DEFAULT_DEBUG_PORT = 9421;
const DEFAULT_CDP_PORT = 62000;

/**
 * 注入代理：Node 侧不再直接依赖 frida 原生模块，
 * 而是拉起 Python 3.8 + frida 16.x 的 agent.py，通过 JSON 行通信。
 * 这样在无法访问 GitHub 下载 frida-node 预编译包的环境里也能跑。
 */
class FridaAgent extends EventEmitter {
    private child: ChildProcess | null = null;
    private stderr = "";
    private stopped = false;

    start(options: { root: string; hook: string; debugPort: number; autoDetect: boolean }) {
        return new Promise<{ pid: number; version: number; config: unknown; source: "file" | "auto" }>(
            (resolve, reject) => {
                const python = resolvePython();
                const agentPath = path.join(options.root, "agent", "agent.py");
                if (!existsSync(agentPath)) {
                    reject(new Error(`找不到注入代理: ${agentPath}`));
                    return;
                }

                const args = [
                    agentPath,
                    "--root", options.root,
                    "--hook", options.hook,
                    "--debug-port", String(options.debugPort),
                ];
                if (options.autoDetect) args.push("--auto-detect");

                this.emit("log", "info", `[agent] 使用 ${python.display}`);
                const child = spawn(python.command, [...python.args, ...args], {
                    cwd: options.root,
                    stdio: ["pipe", "pipe", "pipe"],
                    windowsHide: true,
                });
                this.child = child;

                let pid = 0;
                let version = 0;
                let config: unknown = null;
                let source: "file" | "auto" = "file";
                let settled = false;

                const timer = setTimeout(() => {
                    if (settled) return;
                    settled = true;
                    this.kill();
                    reject(new Error("注入超时（120s），请检查微信是否在运行、Node 与微信权限是否一致"));
                }, 120000);

                const fail = (message: string) => {
                    if (settled) return;
                    settled = true;
                    clearTimeout(timer);
                    this.kill();
                    reject(new Error(message));
                };

                let buffer = "";
                child.stdout?.setEncoding("utf8");
                child.stdout?.on("data", (chunk: string) => {
                    buffer += chunk;
                    let index: number;
                    while ((index = buffer.indexOf("\n")) >= 0) {
                        const line = buffer.slice(0, index).trim();
                        buffer = buffer.slice(index + 1);
                        if (!line) continue;
                        let message: any;
                        try {
                            message = JSON.parse(line);
                        } catch {
                            continue;
                        }

                        switch (message.event) {
                            case "hello": {
                                const hello = message as AgentHello;
                                pid = hello.pid;
                                version = hello.version;
                                this.emit("hello", hello);
                                break;
                            }
                            case "log":
                                this.emit("log", message.level ?? "info", message.message ?? "");
                                break;
                            case "config": {
                                const cfg = message as AgentConfig;
                                config = cfg.config;
                                source = cfg.source;
                                this.emit("config", { source, config });
                                break;
                            }
                            case "script":
                                this.emit("script", message.payload);
                                break;
                            case "ready": {
                                if (settled) break;
                                settled = true;
                                clearTimeout(timer);
                                resolve({ pid, version, config, source });
                                break;
                            }
                            case "error":
                                fail(message.message || "注入失败");
                                break;
                            case "exit":
                                if (!settled) fail(this.stderr.trim() || "注入代理提前退出");
                                break;
                        }
                    }
                });

                child.stderr?.setEncoding("utf8");
                child.stderr?.on("data", (chunk: string) => {
                    this.stderr += chunk;
                    if (this.stderr.length > 8000) this.stderr = this.stderr.slice(-8000);
                });

                child.on("error", (err) => fail(`无法启动注入代理: ${err.message}`));
                child.on("exit", (code) => {
                    this.child = null;
                    if (!settled) {
                        fail(this.stderr.trim() || `注入代理退出，code=${code}`);
                    } else {
                        this.emit("exit", code);
                    }
                });
            },
        );
    }

    stop() {
        this.stopped = true;
        const child = this.child;
        if (!child) return Promise.resolve();
        return new Promise<void>((resolve) => {
            const timer = setTimeout(() => {
                this.kill();
                resolve();
            }, 4000);
            child.once("exit", () => {
                clearTimeout(timer);
                resolve();
            });
            try {
                child.stdin?.write('{"cmd":"stop"}\n');
                child.stdin?.end();
            } catch {
                this.kill();
                clearTimeout(timer);
                resolve();
            }
        });
    }

    private kill() {
        const child = this.child;
        if (!child) return;
        try {
            child.kill();
        } catch {
            /* ignore */
        }
        this.child = null;
    }
}

function resolvePython(): { command: string; args: string[]; display: string } {
    const env = process.env.WMPF_PYTHON;
    if (env && existsSync(env)) {
        return { command: env, args: [], display: env };
    }

    // 优先 PATH 里的 python（需要已安装 frida），找不到再退回常见安装路径
    try {
        const output = execFileSync("where", ["python"], { encoding: "utf8", windowsHide: true });
        for (const line of output.split(/\r?\n/)) {
            const candidate = line.trim();
            if (candidate && existsSync(candidate) && !candidate.includes("WindowsApps")) {
                return { command: candidate, args: [], display: candidate };
            }
        }
    } catch {
        /* where 不可用时走下面的候选 */
    }

    const candidates = [
        path.join(process.env.LOCALAPPDATA ?? "", "Programs", "Python", "Python313", "python.exe"),
        path.join(process.env.LOCALAPPDATA ?? "", "Programs", "Python", "Python312", "python.exe"),
        path.join(process.env.LOCALAPPDATA ?? "", "Programs", "Python", "Python311", "python.exe"),
        path.join(process.env.LOCALAPPDATA ?? "", "Programs", "Python", "Python38", "python.exe"),
    ].filter((item) => Boolean(item));

    for (const candidate of candidates) {
        if (existsSync(candidate)) {
            return { command: candidate, args: [], display: candidate };
        }
    }
    return { command: "python", args: [], display: "python" };
}

export class StudioController extends EventEmitter {
    readonly logs = new LogBus();

    private debugWss: WebSocketServer | null = null;
    private proxyWss: WebSocketServer | null = null;
    private proxyHttp: http.Server | null = null;
    private agent = new FridaAgent();
    private state: StudioState = "idle";
    private version: number | null = null;
    private pid: number | null = null;
    private error: string | null = null;
    private startedAt: number | null = null;
    private configSource: "file" | "auto-detect" | "none" = "none";
    private messageCounter = 0;
    private frameCount = 0;
    private proxySeq = 100000 + Math.floor(Math.random() * 500000);
    private cdpClients = new Map<WebSocket, { pending: Map<number, number>; url: string }>();

    debugPort = DEFAULT_DEBUG_PORT;
    cdpPort = DEFAULT_CDP_PORT;

    constructor() {
        super();
        this.agent.on("log", (level, message) => this.logs.push(level, message));
        this.agent.on("hello", (hello: AgentHello) => {
            this.pid = hello.pid;
            this.version = hello.version;
            this.emit("status", this.status());
        });
        this.agent.on("config", ({ source }) => {
            this.configSource = source === "auto" ? "auto-detect" : "file";
        });
        this.agent.on("script", (payload) => this.logs.frida(String(payload)));
        this.agent.on("exit", () => {
            if (this.state === "ready") this.setState("error", "注入进程已退出");
        });
    }

    status(): StudioStatus {
        return {
            state: this.state,
            version: this.version,
            pid: this.pid,
            debugPort: this.debugPort,
            cdpPort: this.cdpPort,
            cdpUrl: `ws://127.0.0.1:${this.cdpPort}`,
            devtoolsUrl: `devtools://devtools/bundled/js_app.html?ws=127.0.0.1:${this.cdpPort}`,
            configSource: this.configSource,
            error: this.error,
            startedAt: this.startedAt,
            clients: {
                cdp: this.proxyWss ? this.proxyWss.clients.size : 0,
                miniapp: this.debugWss ? this.debugWss.clients.size : 0,
            },
        };
    }

    /**
     * 内置 Console：起一个临时 CDP 客户端连本机代理，执行完就关。
     * 注意 WMPF 这个构建下 awaitPromise 会崩，所以只能同步求值。
     */
    evaluate(expression: string): Promise<{ ok: boolean; result?: unknown; error?: string }> {
        return new Promise((resolve) => {
            const ws = new WebSocket(`ws://127.0.0.1:${this.cdpPort}/devtools/page/appservice`);
            let settled = false;
            const finish = (value: { ok: boolean; result?: unknown; error?: string }) => {
                if (settled) return;
                settled = true;
                clearTimeout(timer);
                try {
                    ws.close();
                } catch {
                    /* ignore */
                }
                resolve(value);
            };
            const timer = setTimeout(() => finish({ ok: false, error: "执行超时（6s）" }), 6000);

            ws.on("open", () => {
                ws.send(JSON.stringify({
                    id: 1,
                    method: "Runtime.evaluate",
                    params: { expression, returnByValue: true, awaitPromise: false, userGesture: true },
                }));
            });
            ws.on("message", (data: WebSocket.RawData) => {
                let message: any;
                try {
                    message = JSON.parse(data.toString());
                } catch {
                    return;
                }
                if (message.id !== 1) return;
                if (message.error) {
                    finish({ ok: false, error: message.error.message || "CDP 错误" });
                    return;
                }
                const result = message.result || {};
                if (result.exceptionDetails) {
                    const detail = result.exceptionDetails;
                    finish({
                        ok: false,
                        error: (detail.exception && (detail.exception.description || detail.exception.value)) || detail.text || "JS 异常",
                    });
                    return;
                }
                finish({ ok: true, result: result.result });
            });
            ws.on("error", (err) => finish({ ok: false, error: err.message }));
            ws.on("close", () => finish({ ok: false, error: "连接已关闭" }));
        });
    }

    private setState(state: StudioState, error: string | null = null) {
        this.state = state;
        this.error = error;
        this.emit("status", this.status());
    }

    async start(options: { autoDetect?: boolean } = {}): Promise<StudioStatus> {
        if (this.state === "starting" || this.state === "ready") return this.status();
        this.setState("starting");
        this.logs.info(`[studio] 启动中，调试端口 ${this.debugPort}，CDP 端口 ${this.cdpPort}`);

        try {
            this.startServers();
            const result = await this.agent.start({
                root: projectRoot(),
                hook: path.join(projectRoot(), "frida", "hook.js"),
                debugPort: this.debugPort,
                autoDetect: options.autoDetect !== false,
            });
            this.pid = result.pid;
            this.version = result.version;
            this.configSource = result.source === "auto" ? "auto-detect" : "file";
            this.startedAt = Date.now();
            this.setState("ready");
            this.logs.info("[studio] 已就绪，现在可以打开小程序");
            return this.status();
        } catch (e) {
            const message = e instanceof Error ? e.message : String(e);
            this.logs.error(`[studio] 启动失败: ${message}`);
            await this.cleanup();
            this.setState("error", message);
            return this.status();
        }
    }

    async stop(): Promise<StudioStatus> {
        this.logs.info("[studio] 正在停止…");
        await this.cleanup();
        this.startedAt = null;
        this.setState("idle");
        return this.status();
    }

    private startServers() {
        this.debugWss = new WebSocketServer({ port: this.debugPort });
        this.logs.info(`[server] 小程序调试通道 ws://localhost:${this.debugPort}`);

        this.debugWss.on("connection", (ws: WebSocket) => {
            this.logs.info("[miniapp] 小程序已连接");
            this.emit("status", this.status());
            ws.on("message", (data: WebSocket.RawData) => this.onMiniappMessage(data as ArrayBuffer));
            ws.on("error", (err) => this.logs.error("[miniapp] 通道错误", err.message));
            ws.on("close", () => {
                this.logs.info("[miniapp] 小程序断开");
                this.emit("status", this.status());
            });
        });

        this.proxyHttp = http.createServer((req, res) => {
            const target = `ws://127.0.0.1:${this.cdpPort}/devtools/page/appservice`;
            const frontend = `devtools://devtools/bundled/js_app.html?ws=127.0.0.1:${this.cdpPort}/devtools/page/appservice`;
            res.setHeader("Content-Type", "application/json; charset=utf-8");
            res.setHeader("Access-Control-Allow-Origin", "*");

            if (req.url?.startsWith("/json/list") || req.url === "/json") {
                res.end(JSON.stringify([
                    {
                        id: "appservice",
                        type: "node",
                        title: "小程序逻辑层 (V8)",
                        description: "WMPF AppService",
                        url: "wmpf://appservice",
                        webSocketDebuggerUrl: target,
                        devtoolsFrontendUrl: frontend,
                    },
                ]));
                return;
            }
            if (req.url?.startsWith("/json/version")) {
                res.end(JSON.stringify({
                    Browser: "WMPF/2.2.0",
                    "Protocol-Version": "1.3",
                    "User-Agent": "WMPF",
                    "V8-Version": "0",
                    "WebKit-Version": "0",
                    webSocketDebuggerUrl: `ws://127.0.0.1:${this.cdpPort}/devtools/browser`,
                }));
                return;
            }
            res.statusCode = 404;
            res.end("{}");
        });
        this.proxyWss = new WebSocketServer({ server: this.proxyHttp });
        this.proxyHttp.listen(this.cdpPort, "127.0.0.1");
        this.logs.info(`[server] CDP 代理 ws://127.0.0.1:${this.cdpPort}（同时提供 /json/list）`);

        this.proxyWss.on("connection", (ws: WebSocket, req: http.IncomingMessage) => {
            const ua = String(req.headers["user-agent"] ?? "").slice(0, 70);
            this.logs.info(`[cdp] 新连接 url=${req.url} origin=${req.headers.origin ?? "-"} ua=${ua}`);
            this.cdpClients.set(ws, { pending: new Map(), url: req.url ?? "" });
            this.emit("status", this.status());

            ws.on("message", (data: WebSocket.RawData) => {
                const text = data.toString();
                this.logs.debug("[cdp→] " + text.slice(0, 180));
                const state = this.cdpClients.get(ws);
                if (!state) return;
                let message: any;
                try {
                    message = JSON.parse(text);
                } catch {
                    this.emit("proxymessage", text);
                    return;
                }
                // /devtools/browser 是 Node 前端的探测连接，WMPF 没有 browser target，直接回错误
                if (state.url.startsWith("/devtools/browser")) {
                    if (typeof message.id === "number") {
                        ws.send(JSON.stringify({
                            id: message.id,
                            error: { code: -32601, message: "browser target is not supported by WMPF" },
                        }));
                    }
                    return;
                }
                // CDP id 多路复用：每个客户端独立 id 空间，避免小程序报 Duplicate id
                if (typeof message.id === "number") {
                    const proxyId = ++this.proxySeq;
                    state.pending.set(proxyId, message.id);
                    message.id = proxyId;
                    this.emit("proxymessage", JSON.stringify(message));
                } else {
                    this.emit("proxymessage", text);
                }
            });
            ws.on("error", (err) => this.logs.error("[cdp] 通道错误", err.message));
            ws.on("close", () => {
                this.cdpClients.delete(ws);
                this.logs.info("[cdp] DevTools 断开");
                this.emit("status", this.status());
            });
        });

        this.on("proxymessage", (message: string) => {
            if (!this.debugWss) return;
            for (const client of this.debugWss.clients) {
                if (client.readyState !== WebSocket.OPEN) continue;
                const rawPayload = {
                    jscontext_id: "",
                    op_id: Math.round(100 * Math.random()),
                    payload: message.toString(),
                };
                const wrappedData = codex.wrapDebugMessageData(rawPayload, "chromeDevtools", 0);
                const encodedData = messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.encode({
                    seq: ++this.messageCounter,
                    category: "chromeDevtools",
                    data: wrappedData.buffer,
                    compressAlgo: 0,
                    originalSize: wrappedData.originalSize,
                }).finish();
                client.send(encodedData, { binary: true });
            }
        });
    }

    private onMiniappMessage(message: ArrayBuffer) {
        try {
            const decoded = messageProto.mmbizwxadevremote.WARemoteDebug_DebugMessage.decode(message);
            const unwrapped = codex.unwrapDebugMessageData(decoded);
            if (unwrapped) {
                const payload = (unwrapped.data && unwrapped.data.payload) || "";
                if (unwrapped.category !== "chromeDevtoolsResult") {
                    this.logs.debug(`[miniapp←] ${unwrapped.category} len=${message.byteLength}`);
                } else if (this.frameCount++ % 200 === 0) {
                    this.logs.debug(`[miniapp←] 已转发 ${this.frameCount} 帧，最近一条 ${String(payload).slice(0, 100)}`);
                }
                if (unwrapped.category === "chromeDevtoolsResult") {
                    this.routeCdpmessage(payload);
                }
            }
        } catch {
            this.logs.debug(`[miniapp←] 解码失败 len=${message.byteLength}`);
        }
    }

    /**
     * 响应路由：按 id 映射还原后只回给发起请求的那个客户端；
     * 无 id 的事件（Debugger.scriptParsed、Network.* 等）广播给所有客户端。
     */
    private routeCdpmessage(payload: string) {
        let message: any;
        try {
            message = JSON.parse(payload);
        } catch {
            this.broadcastCdp(payload);
            return;
        }

        if (typeof message.id === "number") {
            for (const [ws, state] of this.cdpClients) {
                const originalId = state.pending.get(message.id);
                if (originalId === undefined) continue;
                state.pending.delete(message.id);
                message.id = originalId;
                if (ws.readyState === WebSocket.OPEN) {
                    ws.send(JSON.stringify(message));
                }
                return;
            }
            this.broadcastCdp(payload);
            return;
        }

        this.broadcastCdp(payload);
    }

    private broadcastCdp(payload: string) {
        for (const ws of this.cdpClients.keys()) {
            if (ws.readyState === WebSocket.OPEN) {
                ws.send(payload);
            }
        }
    }

    private async cleanup() {
        await this.agent.stop();

        for (const server of [this.debugWss, this.proxyWss]) {
            if (!server) continue;
            for (const client of server.clients) {
                try {
                    client.close();
                } catch {
                    /* ignore */
                }
            }
            await new Promise<void>((resolve) => server.close(() => resolve()));
        }
        if (this.proxyHttp) {
            await new Promise<void>((resolve) => this.proxyHttp?.close(() => resolve()));
            this.proxyHttp = null;
        }
        this.debugWss = null;
        this.proxyWss = null;
        this.pid = null;
        this.version = null;
        this.configSource = "none";
    }
}

function projectRoot(): string {
    // pkg 打包后 __dirname 在快照里，资源放在 exe 同级目录
    if ((process as unknown as { pkg?: string }).pkg) {
        return path.dirname(process.execPath);
    }
    // 便携打包后 app.cjs 与 web/ 同级；开发时 __dirname 在 src/studio
    if (existsSync(path.join(__dirname, "web"))) {
        return __dirname;
    }
    return path.resolve(__dirname, "..", "..");
}
