"""测试包专用：把 Runner 的公网隧道改接到「控制面」，并提供任务内网渠道的反代。

Runner 自身的 Quick Tunnel 只允许指向 Gateway；受控隧道是逐 run 独立控制的，
但有代价——它会把 Gateway 的路由原样暴露（`/v1/state/import` 等会落到我们自己的
插件上）。本补丁把 `Supervisor.gateway_url` 换成 `http://127.0.0.1`，并在同一个
aiohttp 应用上、router 冻结**之前**加两条路由：

- `/x/{token}/{run_id}/<port>/<path>`：反代到 `127.0.0.1:<port>`（任务的内网渠道）；
- 其余路径一律 404：隧道只当控制面，别的公网请求看不到 Gateway 的任何接口。

只改任务包里的 `_gha_runtime` 副本，不触碰工作区源码。
"""

from aiohttp import web

TARGET_PREFIX = "/x/"


def install(app):
    """Supervisor.__init__ 里调用：登记路由（此时 router 还没冻结）。"""
    app.app.router.add_route("*", r"/x/{token}/{run_id:\d+}/{port:\d+}/{tail:.*}", _reverse)
    app.app.router.add_route("*", "/{tail:.*}", _closed)
    print("[runtime] e2e control tunnel routes installed", flush=True)


async def _reverse(request):
    port = request.match_info["port"]
    rest = request.match_info.get("tail") or ""
    body = await request.read()
    headers = {"Content-Type": request.headers.get("Content-Type", "application/json"),
               "X-E2E-Secret": request.headers.get("X-E2E-Secret", ""),
               "Authorization": request.headers.get("Authorization", ""),
               "Content-Length": str(len(body)),
               "Connection": "close"}
    import asyncio
    import urllib.error
    import urllib.request

    target = "http://127.0.0.1:%s/%s" % (port, rest)
    # request.query_string 是解码后的值，含空格/引号时 urllib 会判 InvalidURL；
    # raw_query_string 保留百分号编码，原样转发才是 Host 实际发出的查询
    raw_query = getattr(request.rel_url, "raw_query_string", "") or request.query_string
    if raw_query:
        target += "?" + raw_query
    req = urllib.request.Request(target, data=body or None, headers=headers,
                                 method=request.method)

    def _forward():
        # 上游用默认代理会 hang 到超时；与 aiohttp 同一个 30s 上限
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=30) as resp:
                return (resp.status, resp.read(),
                        resp.headers.get("Content-Type", "application/json"),
                        resp.headers.get("Content-Range", ""))
        except urllib.error.HTTPError as exc:
            return (exc.code, exc.read(),
                    exc.headers.get("Content-Type", "application/json"), "")
    try:
        status, data, ctype, crange = await asyncio.get_running_loop().run_in_executor(None, _forward)
        headers_out = {"Content-Type": ctype}
        if crange:
            headers_out["Content-Range"] = crange
        return web.Response(body=data, status=status, headers=headers_out)
    except Exception as exc:
        return web.json_response({"error": "channel unreachable: %s" % type(exc).__name__}, status=502)


async def _closed(request):
    return web.json_response({"error": "not found"}, status=404)
