// Handoff 门户前端：同一个页面服务 Browser / Desktop 两种接管。
//
// - ?mode=browser（默认）：/v1/live/browser WebSocket 画面 + Canvas 输入中继；
// - ?mode=desktop：动态加载 /web/novnc/core/rfb.js，连 /v1/live/desktop；
// - 切换模式只换画面通道，不刷新页面、不重启 Chromium / 桌面；
// - Ticket 只从 location.hash 读取，认领成功后从地址栏抹掉；
// - 交还调用 /v1/handoff/complete，Gateway 停止 x11vnc/websockify，桌面保持运行。
(function () {
  "use strict";

  const canvas = document.getElementById("stream-canvas");
  const ctx = canvas.getContext("2d");
  const viewport = document.getElementById("viewport-container");
  const btnComplete = document.getElementById("btn-complete");
  const connStatus = document.getElementById("conn-status");
  const genTag = document.getElementById("gen-tag");
  const modeBadge = document.getElementById("mode-badge");
  const hint = document.getElementById("hint");

  const params = new URLSearchParams(window.location.search);
  let mode = params.get("mode") === "desktop" ? "desktop" : "browser";

  // 世代：认领成功后的状态机世代；输入中继只在世代一致时有效。
  let generation = 1;
  let browserWs = null;
  let rfb = null;
  let screenHost = null;
  let completeInFlight = false;

  function setConn(text, ok) {
    const dot = ok ? "#238636" : "#da3633";
    connStatus.innerHTML = `<span class="status-dot" style="background:${dot}"></span>${text}`;
  }

  function applyModeText() {
    modeBadge.textContent = mode === "desktop" ? "Desktop Handoff" : "Browser Handoff";
    hint.textContent = mode === "desktop"
      ? "提示：画面经 Xvfb → x11vnc → noVNC 传输，可直接操作桌面应用与系统对话框。交还后 x11vnc 关闭，桌面与 Chromium 继续运行。"
      : "提示：在此区域点击或键盘输入将实时同步到 Runner 浏览器。点击右上角交还控制权即可继续任务。";
  }

  function setMode(next) {
    if (next === mode && (browserWs || rfb)) return;
    teardownStream();
    mode = next;
    const url = new URL(window.location.href);
    url.searchParams.set("mode", next);
    url.hash = "";
    history.replaceState(null, "", url.pathname + url.search);
    applyModeText();
    startStream();
  }

  function teardownStream() {
    if (browserWs) {
      browserWs.onclose = null;
      browserWs.close();
      browserWs = null;
    }
    if (rfb) {
      try { rfb.disconnect(); } catch (e) { /* 已断开 */ }
      rfb = null;
    }
    if (screenHost) {
      screenHost.remove();
      screenHost = null;
    }
    canvas.classList.remove("hidden");
    btnComplete.disabled = true;
  }

  function wsUrl(path) {
    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    return `${proto}//${window.location.host}${path}`;
  }

  // 1. 认领 Ticket（只从 fragment 读取），换取 HttpOnly 会话 Cookie 与世代。
  function claimTicket() {
    const ticket = new URLSearchParams(window.location.hash.replace(/^#/, "")).get("ticket");
    const request = ticket
      ? fetch("/v1/handoff/claim", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ticket }),
        }).then((r) => ({ ok: r.ok, status: r.status, json: () => r.json() }))
      : fetch("/v1/session", { credentials: "same-origin" })
          .then((r) => ({ ok: r.ok, status: r.status, json: () => r.json() }));

    return request.then((r) => {
      if (!r.ok) {
        const message = r.status === 403 ? "接管票据无效或已过期" : `认领失败（HTTP ${r.status}）`;
        setConn(message, false);
        throw new Error(message);
      }
      return r.json();
    }).then((data) => {
      if (typeof data.generation === "number") {
        generation = data.generation;
        genTag.innerText = `世代: gen-${generation}`;
      }
      if (data.mode && data.mode !== mode) {
        setMode(data.mode === "desktop" ? "desktop" : "browser");
      }
      if (window.location.hash) {
        history.replaceState(null, "", window.location.pathname + window.location.search);
      }
      return data;
    });
  }

  // 2. Browser 画面流与输入中继
  function startBrowser() {
    const ws = new WebSocket(wsUrl("/v1/live/browser"));
    ws.binaryType = "blob";
    browserWs = ws;
    ws.onopen = () => {
      setConn("已连接", true);
      btnComplete.disabled = false;
    };
    ws.onmessage = async (evt) => {
      if (!(evt.data instanceof Blob)) return;
      try {
        const bmp = await createImageBitmap(evt.data);
        ctx.drawImage(bmp, 0, 0, canvas.width, canvas.height);
      } catch (e) { /* 跳过坏帧 */ }
    };
    ws.onclose = () => {
      if (browserWs !== ws) return;
      browserWs = null;
      setConn("连接断开，正在重连…", false);
      setTimeout(() => { if (mode === "browser" && !browserWs) startBrowser(); }, 2000);
    };
  }

  // 3. Desktop 画面流：动态加载 noVNC core/rfb.js，连 Gateway 的 /v1/live/desktop。
  async function startDesktop() {
    setConn("正在加载 noVNC…", true);
    let RFB;
    try {
      RFB = (await import("/web/novnc/core/rfb.js")).default;
    } catch (e) {
      setConn("noVNC 资源缺失（/web/novnc/core/rfb.js）", false);
      return;
    }
    if (mode !== "desktop") return;
    canvas.classList.add("hidden");
    screenHost = document.createElement("div");
    viewport.appendChild(screenHost);
    const client = new RFB(screenHost, wsUrl("/v1/live/desktop"), { shared: true, credentials: {} });
    client.scaleViewport = true;
    client.resizeSession = false;
    client.focusOnClick = true;
    rfb = client;
    client.addEventListener("connect", () => {
      setConn("已连接（同一桌面）", true);
      btnComplete.disabled = false;
      screenHost.focus();
    });
    client.addEventListener("disconnect", () => {
      if (rfb !== client) return;
      rfb = null;
      setConn("桌面连接已断开", false);
    });
  }

  function startStream() {
    if (mode === "desktop") startDesktop();
    else startBrowser();
  }

  // 4. Canvas 输入（仅 browser 模式）
  function canvasCoords(e) {
    const rect = canvas.getBoundingClientRect();
    return {
      x: Math.round((e.clientX - rect.left) * canvas.width / rect.width),
      y: Math.round((e.clientY - rect.top) * canvas.height / rect.height),
    };
  }

  canvas.addEventListener("click", (e) => {
    if (mode !== "browser" || !browserWs || browserWs.readyState !== WebSocket.OPEN) return;
    const pt = canvasCoords(e);
    browserWs.send(JSON.stringify({
      type: "mouse", event: "click", x: pt.x, y: pt.y,
      button: e.button === 2 ? "right" : "left", generation,
    }));
  });

  canvas.addEventListener("keydown", (e) => {
    if (mode !== "browser" || !browserWs || browserWs.readyState !== WebSocket.OPEN) return;
    browserWs.send(JSON.stringify({
      type: "key", event: "press", key: e.key,
      text: e.key.length === 1 ? e.key : null, generation,
    }));
  });

  // 5. 交还控制权：Gateway 停流并恢复 Agent；不重启桌面/Chromium。
  btnComplete.addEventListener("click", () => {
    if (completeInFlight) return;
    completeInFlight = true;
    btnComplete.disabled = true;
    const original = btnComplete.innerText;
    btnComplete.innerText = "正在交还控制权…";
    fetch("/v1/handoff/complete", { method: "POST", credentials: "same-origin" })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((data) => {
        teardownStream();
        if (typeof data.generation === "number") {
          genTag.innerText = `世代: gen-${data.generation}`;
        }
        btnComplete.innerText = "已交还控制权";
        setConn(mode === "desktop" ? "已交还 Agent，桌面仍在运行" : "已交还 Agent，Chromium 仍在运行", true);
      })
      .catch((err) => {
        btnComplete.disabled = false;
        btnComplete.innerText = original;
        setConn(`交还失败：${err.message}`, false);
      })
      .finally(() => { completeInFlight = false; });
  });

  modeBadge.textContent = mode === "desktop" ? "Desktop Handoff" : "Browser Handoff";
  applyModeText();
  // 同一标签页里只改 fragment 打开新票据时浏览器不会重新加载页面，这里补一次认领。
  window.addEventListener("hashchange", () => {
    if (window.location.hash) claimTicket().catch(() => null);
  });
  claimTicket()
    .catch(() => null)
    .then(() => {
      // 没有 ticket 且没有会话 Cookie 时仍然连流：Gateway 会以 401 关闭连接并显示未连接，
      // 不会伪造“已接管”。
      startStream();
    });
})();
