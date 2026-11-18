import { spawn } from "node:child_process";
import { StudioController } from "./studio/controller";
import { createStudioServer, UI_PORT } from "./studio/server";

const openBrowser = (url: string) => {
    try {
        const child = spawn("cmd", ["/c", "start", "", url], {
            detached: true,
            stdio: "ignore",
            windowsVerbatimArguments: true,
        });
        child.unref();
    } catch {
        /* 打不开就算了，用户自己访问 */
    }
};

const main = async () => {
    const controller = new StudioController();
    const { listen } = createStudioServer(controller);

    try {
        await listen();
    } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        console.error(`[studio] 控制台端口 ${UI_PORT} 启动失败：${message}`);
        console.error(`[studio] 可能已经有实例在运行，先访问 http://127.0.0.1:${UI_PORT}/ 看看`);
        process.exit(1);
    }

    const url = `http://127.0.0.1:${UI_PORT}/`;
    console.log("");
    console.log("  WMPF Debugger Studio");
    console.log(`  控制台已启动: ${url}`);
    console.log("  关闭此窗口或按 Ctrl+C 退出");
    console.log("");

    openBrowser(url);

    const shutdown = async () => {
        console.log("\n[studio] 正在退出…");
        try {
            await controller.stop();
        } catch {
            /* ignore */
        }
        process.exit(0);
    };

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
};

main();
