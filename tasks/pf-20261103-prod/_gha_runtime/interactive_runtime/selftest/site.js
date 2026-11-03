// 自查用「终端用户页面」宿主：监听 127.0.0.1，由 Xvfb 上的浏览器渲染和交互。
//
// 只服务于 interactive_runtime/selftest，不是产品页面。它只需要提供两样东西：
//   1. 一个真实的输入框（#loop-probe）与按钮（#loop-open），供 noVNC 转发的
//      真实鼠标/键盘事件命中（与开发网站时本机起服务同一条路径）；
//   2. 点击按钮后弹出的同进程窗口，供 xdotool 以「窗口 + 键盘」的方式操作，
//      对应人工接管时遇到的系统弹窗 / 二次验证对话框。
//
// 弹窗宿主：HANDOFF_SITE_HOST=x11 时点按钮会 spawn 原生 X11 对话框（xdialog）；
// 默认 HANDOFF_SITE_HOST=jsdom 时用 Node + jsdom 在进程内模拟 DOM 窗口（无 X 环境
// 也能验证回调链路）。两者都只接受键盘，不接受可编辑输入 —— 与系统凭据对话框一致。
"use strict";

const http = require("http");
const { spawn } = require("child_process");
const fs = require("fs");

const PORT = Number(process.env.HANDOFF_SITE_PORT);
const HOST = process.env.HANDOFF_SITE_HOST || "jsdom";
const DIALOG_TITLE = "gha-runner 接管自测";

const PAGE = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>终端用户页面（自查）</title></head>
<body style="margin:0;font-family:system-ui,sans-serif;background:#ffffff">
<h1 style="margin:24px">手动交接测试</h1>
<p style="margin:0 24px;color:#57606a">用户名在此输入框中进入。</p>
<label style="display:block;margin:24px">用户名
  <input id="loop-probe" style="font-size:20px;padding:6px;width:280px;margin-left:8px" autocomplete="off"></label>
<button id="loop-open" style="margin:24px;font-size:18px;padding:6px 16px">打开二次验证弹窗</button>
<pre id="__result" style="margin:24px"></pre>
<script>
  const report = (t) => { document.getElementById('__result').textContent = t;
    fetch('/state', {method: 'POST', body: t}); };
  document.getElementById('loop-open').addEventListener('click', () => {
    fetch('/dialog', {method: 'POST'}).then(() => report('dialog-opened'));
  });
  window.__dialogConfirmed = (v) => report('dialog-confirmed:' + v);
</script>
</body></html>`;

const state = { dialog: "closed", page: "loaded" };
let dialog = null;

// 原生对话框的参数因工具而异：xdialog 用 --msgbox，xmessage（x11-utils 自带）用
// -buttons <label:code> -default，zenity 用 --info --ok-label。三者都只接受键盘，
// 与系统凭据对话框一致：按 Enter 命中默认按钮并自关。
function dialogArgv(bin) {
    const name = require("path").basename(bin || "");
    const msg = "把下面输入框填好后按回车交接";
    if (name.indexOf("xmessage") === 0) {
        return ["-title", DIALOG_TITLE, "-center", "-buttons", "确定:0",
                "-default", "确定", msg];
    }
    if (name.indexOf("zenity") === 0) {
        return ["--title", DIALOG_TITLE, "--info", "--ok-label", "确定", "--text", msg];
    }
    return ["--title", DIALOG_TITLE, "--msgbox", msg, "确定", "6"];
}

function openDialog() {
    if (HOST === "x11") {
        const bin = process.env.HANDOFF_DIALOG_BIN || "xdialog";
        dialog = spawn(bin, dialogArgv(bin), { env: Object.assign({}, process.env) });
        dialog.on("error", (exc) => {
            state.dialog = "error:" + exc.message;
            console.log("dialog spawn error " + exc.message);
        });
        dialog.on("exit", (code) => { state.dialog = "closed"; console.log("dialog exit " + code); });
    } else {
        // jsdom 弹窗宿主：模拟一个只接受键盘的系统对话框（focus + keydown + 自关）
        const { JSDOM } = require("jsdom");
        const dom = new JSDOM(`<!doctype html><body><div id="d" tabindex="0">${DIALOG_TITLE}</div></body>`,
            { runScripts: "outside-only" });
        dialog = dom.window;
        dom.window.document.getElementById("d").focus();
        dom.window.document.addEventListener("keydown", (e) => {
            if (e.key === "Enter") { state.dialog = "confirmed"; console.log("dialog confirmed"); }
            if (e.key === "Escape") { state.dialog = "closed"; }
        });
    }
    state.dialog = "open";
    return dialog;
}

http.createServer((req, res) => {
    if (req.method === "POST" && req.url === "/dialog") {
        try { openDialog(); } catch (exc) { state.dialog = "error:" + exc.message; }
        res.writeHead(204); res.end(); return;
    }
    if (req.method === "POST" && req.url === "/state") {
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", () => { state.page = body; res.writeHead(204); res.end(); });
        return;
    }
    if (req.url === "/__status") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(Object.assign({}, state, {
            dialog_pid: dialog && dialog.pid ? dialog.pid : null, host: HOST })));
        return;
    }
    if (req.url === "/favicon.ico") { res.writeHead(204); res.end(); return; }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" });
    res.end(PAGE);
}).listen(PORT, "127.0.0.1", () => {
    console.log(`site listening on ${PORT} host=${HOST} page=${PAGE.length}B script=${fs.statSync(__filename).size}B`);
});
