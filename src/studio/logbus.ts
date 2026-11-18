import { EventEmitter } from "node:events";

export type LogLevel = "info" | "error" | "debug" | "frida" | "warn";

export type LogEntry = {
    t: number;
    level: LogLevel;
    message: string;
};

/**
 * 环形日志总线：CLI 输出、SSE 推送、页面回放都走这里。
 */
export class LogBus extends EventEmitter {
    private buffer: LogEntry[] = [];
    private readonly limit: number;

    constructor(limit = 800) {
        super();
        this.setMaxListeners(50);
        this.limit = limit;
    }

    push(level: LogLevel, ...parts: unknown[]) {
        const message = parts
            .map((part) => {
                if (typeof part === "string") return part;
                try {
                    return JSON.stringify(part);
                } catch {
                    return String(part);
                }
            })
            .join(" ");
        const entry: LogEntry = { t: Date.now(), level, message };
        this.buffer.push(entry);
        if (this.buffer.length > this.limit) {
            this.buffer.splice(0, this.buffer.length - this.limit);
        }
        this.emit("entry", entry);
    }

    info(...parts: unknown[]) {
        this.push("info", ...parts);
    }

    error(...parts: unknown[]) {
        this.push("error", ...parts);
    }

    warn(...parts: unknown[]) {
        this.push("warn", ...parts);
    }

    debug(...parts: unknown[]) {
        this.push("debug", ...parts);
    }

    frida(...parts: unknown[]) {
        this.push("frida", ...parts);
    }

    snapshot(): LogEntry[] {
        return this.buffer.slice();
    }
}
