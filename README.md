# 小程序调试抓包工具（WMPF Debugger Studio）

PC 微信小程序调试器。注入 `WeChatAppEx.exe`，打开远程调试通道，用 Chromium DevTools 调试小程序的逻辑层：看源码、下断点、看调用栈、看网络请求。

> 本项目基于 [WMPFDebugger](https://github.com/evi0s/WMPFDebugger) 二次开发，原作者 evi0s，协议 GPLv2。
> 本仓库的修改部分同样遵循 GPLv2。原项目解决的是注入与调试通道，本项目补充了控制台界面、版本自动适配、一键打开 DevTools 和打包。

## 功能

- 在 Sources 面板查看逻辑层 JS，下断点、单步、看调用栈
- Console 直接执行 JS，读写小程序的全局变量
- Network 面板查看请求与响应
- 没有该版本的偏移配置时，自动探测并缓存
- 一键拉起内置 Chromium 并连接 DevTools
- 控制台页面：启动/停止、连接状态、分级日志

## 环境要求

- Windows 10 / 11
- Node.js 20 及以上
- Python 3.8 及以上，并安装 frida 17：

```bash
pip install "frida>=17"
```

> 注入代理是 Python 脚本（`agent/agent.py`），由 Node 侧调用系统 Python 启动。
> 如果机器上有多个 Python，可用环境变量 `WMPF_PYTHON` 指定解释器路径。

## 运行

```bash
npm install
npm run studio
```

浏览器打开 `http://127.0.0.1:63000`，然后：

1. 点「启动调试」
2. 在微信里打开任意小程序
3. 点「打开 DevTools」

## 关于 DevTools

Chrome 157 起，所有 Chromium 系浏览器都禁止从外部进程打开 `devtools://` 和 `chrome://inspect`（命令行传入会被降级成新标签页）。

因此需要随包附带一个旧版 Chromium 作为宿主：

- 把 Chromium 解压到项目根目录的 `chromium/`，确保存在 `chromium/chrome.exe`
- 点「打开 DevTools」时，程序会用它启动远程调试端口，再通过 `PUT /json/new` 创建 DevTools 标签页

没有 `chromium/` 时，程序会退化为提示手动进 `chrome://inspect`。

可用的 Chromium 快照（2021 版，Chrome 92，已验证）：

```
https://cdn.npmmirror.com/binaries/chromium-browser-snapshots/Win_x64/884014/chrome-win.zip
```

解压后把 `chrome-win/` 里的内容放到 `chromium/` 下即可。

## 目录结构

```
src/
  studio-main.ts        控制台入口
  studio/controller.ts  注入控制、CDP 多路复用、内置 Console
  studio/server.ts      本地 HTTP / SSE / 静态页面
  studio/logbus.ts      日志总线
  web/index.html        控制台页面
  third-party/          原项目的协议编解码（RemoteDebugCodex 等）
agent/agent.py          Frida 注入代理（JSON over stdio）
frida/
  hook.js               注入脚本：改 scene、改调试开关、放行 CDP
  autodetect/win32.js   偏移自动探测
  config/               各版本偏移配置
```

## 免责声明

本工具仅用于调试自己开发或已获得授权的小程序，用于安全研究与学习。

请勿用于未授权调试他人小程序、绕过风控、游戏作弊等场景。使用本工具产生的一切后果由使用者自行承担。

## 协议

GPLv2。原始版权归 WMPFDebugger 作者 evi0s 及贡献者所有。
