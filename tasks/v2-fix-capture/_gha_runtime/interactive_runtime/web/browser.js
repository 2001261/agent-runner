// Browser Handoff 前端交互逻辑
(function() {
  const canvas = document.getElementById("stream-canvas");
  const ctx = canvas.getContext("2d");
  const btnComplete = document.getElementById("btn-complete");
  const connStatus = document.getElementById("conn-status");
  const genTag = document.getElementById("gen-tag");

  const fragmentParams = new URLSearchParams(window.location.hash.replace(/^#/, ""));
  const ticket = fragmentParams.get("ticket");
  let generation = 1;

  // 1. 尝试认领 Ticket
  if (ticket) {
    fetch("/v1/handoff/claim", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ticket: ticket })
    })
    .then(r => r.json())
    .then(data => {
      if (data.generation) {
        generation = data.generation;
        genTag.innerText = `世代: gen-${generation}`;
      }
    })
    .catch(console.error);
  }

  // 2. 建立 WebSocket 流
  const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${wsProtocol}//${window.location.host}/v1/live/browser`;
  let ws = null;

  function connect() {
    ws = new WebSocket(wsUrl);
    ws.binaryType = "blob";

    ws.onopen = () => {
      connStatus.innerHTML = '<span class="status-dot"></span>已连接';
    };

    ws.onmessage = async (evt) => {
      if (evt.data instanceof Blob) {
        const bmp = await createImageBitmap(evt.data);
        ctx.drawImage(bmp, 0, 0, canvas.width, canvas.height);
      }
    };

    ws.onclose = () => {
      connStatus.innerHTML = '<span class="status-dot" style="background:#da3633"></span>连接断开，正在重连...';
      setTimeout(connect, 2000);
    };
  }

  connect();

  // 3. 鼠标输入中继
  function getCanvasCoords(e) {
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;
    return {
      x: Math.round((e.clientX - rect.left) * scaleX),
      y: Math.round((e.clientY - rect.top) * scaleY)
    };
  }

  canvas.addEventListener("click", (e) => {
    const pt = getCanvasCoords(e);
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: "mouse",
        event: "click",
        x: pt.x,
        y: pt.y,
        button: e.button === 2 ? "right" : "left",
        generation: generation
      }));
    }
  });

  // 4. 键盘按键中继
  canvas.addEventListener("keydown", (e) => {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({
        type: "key",
        event: "press",
        key: e.key,
        text: e.key.length === 1 ? e.key : null,
        generation: generation
      }));
    }
  });

  // 5. 返还控制权
  btnComplete.addEventListener("click", () => {
    btnComplete.disabled = true;
    btnComplete.innerText = "正在交还控制权...";
    fetch("/v1/handoff/complete", { method: "POST" })
      .then(r => r.json())
      .then(data => {
        alert("控制权已交还 Agent！此页面可以关闭。");
        window.close();
      })
      .catch(err => {
        alert("交还失败: " + err);
        btnComplete.disabled = false;
        btnComplete.innerText = "交还控制权给 Agent";
      });
  });
})();
