#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WMPF Debugger Studio - 注入代理

由 Node 控制台以子进程方式拉起，通过 stdin/stdout 的 JSON 行通信。
这么做是为了绕开 frida-node 的原生模块编译（依赖 GitHub 预编译包）。

协议：
  stdout  {"event":"hello","pid":...,"version":...}
          {"event":"log","level":"info","message":"..."}
          {"event":"config","source":"file|auto","config":{...}}
          {"event":"ready"}
          {"event":"script","payload":...}
          {"event":"error","message":"..."}
          {"event":"exit"}
  stdin   {"cmd":"stop"}

用法：
  python agent.py --root <project> --hook frida/hook.js --debug-port 9421 [--auto-detect]
"""

import argparse
import json
import os
import re
import sys
import threading

import frida

# 强制 UTF-8，避免 Windows 管道下按 GBK 输出
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")


def emit(obj):
    # Windows 下 Python 的 stdout 默认是 GBK，直接写 UTF-8 字节，避免 Node 侧解码乱码
    line = json.dumps(obj, ensure_ascii=False) + "\n"
    sys.stdout.buffer.write(line.encode("utf-8"))
    sys.stdout.buffer.flush()


def log(level, message):
    emit({"event": "log", "level": level, "message": str(message)})


def pick_wmpf(device):
    """复刻 platform/win32.ts：找 WeChatAppEx.exe，取被最多子进程引用的那个父进程。"""
    processes = device.enumerate_processes(scope="metadata")
    wmpf = [p for p in processes if p.name == "WeChatAppEx.exe"]
    if not wmpf:
        raise RuntimeError("没有找到 WeChatAppEx.exe，请先打开微信并随便点开一个小程序")

    counts = {}
    for p in wmpf:
        ppid = int((p.parameters or {}).get("ppid", 0) or 0)
        if ppid:
            counts[ppid] = counts.get(ppid, 0) + 1
    if not counts:
        # 少数 frida 版本拿不到 ppid，退化为取启动最早（pid 最小）的那个
        target_pid = min(p.pid for p in wmpf)
    else:
        target_pid = max(counts.items(), key=lambda kv: kv[1])[0]

    target = next((p for p in processes if p.pid == target_pid), None)
    if target is None:
        raise RuntimeError("没有找到 WMPF 浏览器主进程")

    params = target.parameters or {}
    argv = params.get("argv") or []
    runtime_dir = next((a for a in argv if a.startswith("--flue-runtime-dir")), None)
    path = runtime_dir or params.get("path") or ""
    numbers = re.findall(r"\d+", path)
    version = int(numbers[-1]) if numbers else 0
    if not version:
        raise RuntimeError("无法从路径解析 WMPF 版本: %s" % path)
    return target.pid, version


def run_detector(session, root):
    detector_path = os.path.join(root, "frida", "autodetect", "%s.js" % sys.platform)
    if sys.platform == "win32":
        detector_path = os.path.join(root, "frida", "autodetect", "win32.js")
    elif sys.platform == "darwin":
        detector_path = os.path.join(root, "frida", "autodetect", "darwin.js")
    else:
        detector_path = os.path.join(root, "frida", "autodetect", "linux.js")

    with open(detector_path, "r", encoding="utf-8") as f:
        source = f.read()

    script = session.create_script(source)
    done = threading.Event()
    result = {"config": None, "error": None}

    def on_message(message, data):
        if message.get("type") == "error":
            result["error"] = message.get("description") or "detector error"
            done.set()
            return
        payload = message.get("payload") or {}
        if payload.get("type") == "wmpf-offsets":
            result["config"] = payload.get("config")
            done.set()
        elif payload.get("type") == "wmpf-offsets-error":
            result["error"] = payload.get("error") or "unknown"
            done.set()

    script.on("message", on_message)
    script.load()
    if not done.wait(60):
        script.unload()
        raise RuntimeError("自动探测超时（60s）")
    script.unload()

    if result["error"]:
        raise RuntimeError("自动探测失败: %s" % result["error"])
    return result["config"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--hook", required=True)
    parser.add_argument("--debug-port", type=int, default=9421)
    parser.add_argument("--auto-detect", action="store_true")
    parser.add_argument("--force-auto", action="store_true")
    args = parser.parse_args()

    log("info", "[agent] root=%s hook=%s" % (args.root, args.hook))

    session = None
    try:
        device = frida.get_local_device()
        pid, version = pick_wmpf(device)
        emit({"event": "hello", "pid": pid, "version": version})
        log("info", "[frida] 命中 WeChatAppEx.exe pid=%s，WMPF 版本 %s" % (pid, version))

        session = device.attach(pid)
        log("info", "[frida] 已附加")

        config_path = os.path.join(
            args.root, "frida", "config", "win32", "addresses.%s.json" % version
        )
        if sys.platform == "darwin":
            config_path = os.path.join(
                args.root, "frida", "config", "darwin", "addresses.%s.json" % version
            )

        log("info", "[frida] 配置路径 %s" % config_path)

        config = None
        source_kind = "file"
        if os.path.isfile(config_path) and not args.force_auto:
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    config = json.load(f)
                if not isinstance(config, dict) or "LoadStartHookOffset" not in config:
                    raise ValueError("配置缺少必要字段")
                log("info", "[frida] 使用版本配置 %s" % os.path.basename(config_path))
            except Exception as e:
                log("warn", "[frida] 配置文件无效（%s），改为自动探测" % e)
                config = None

        if config is None:
            log("info", "[frida] 没有可用配置，开始自动探测偏移（可能需要几十秒）…")
            config = run_detector(session, args.root)
            source_kind = "auto"
            log("info", "[frida] 自动探测成功")
            try:
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump(config, f, ensure_ascii=False, indent=4)
                log("info", "[frida] 已缓存配置 %s" % os.path.basename(config_path))
            except Exception as e:
                log("warn", "[frida] 配置缓存失败: %s" % e)

        emit({"event": "config", "source": source_kind, "config": config})

        with open(args.hook, "r", encoding="utf-8") as f:
            hook_source = f.read()
        hook_source = hook_source.replace(
            'const websocketUrl = "ws://localhost:9421";',
            'const websocketUrl = "ws://localhost:%d";' % args.debug_port,
        )
        hook_source = hook_source.replace("@@CONFIG@@", json.dumps(config))

        script = session.create_script(hook_source)

        def on_message(message, data):
            if message.get("type") == "error":
                log("error", "[frida] %s" % message.get("description", "script error"))
                return
            emit({"event": "script", "payload": message.get("payload")})

        script.on("message", on_message)
        script.load()
        log("info", "[frida] hook 已注入，等待小程序连接…")
        emit({"event": "ready"})

        stop_event = threading.Event()

        def reader():
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    cmd = json.loads(line)
                except Exception:
                    continue
                if cmd.get("cmd") == "stop":
                    break
            stop_event.set()

        threading.Thread(target=reader, daemon=True).start()
        stop_event.wait()
    except Exception as e:
        emit({"event": "error", "message": str(e)})
    finally:
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        emit({"event": "exit"})


if __name__ == "__main__":
    main()
