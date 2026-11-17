"""「已知内容」逐帧识别：解密后的录像里必须出现一段指定纯色。

产物录像只有 x11grab 采到真实帧才会出现这块颜色，所以颜色按帧出现即证明
「这段时间的画面确实被录下来了」；它不是产品必需步骤，只在显式指定颜色时启用
（本地实验室把录制区域换成纯色，作为与终端用户窗口同构的可见画面）。
"""

from __future__ import annotations

import re
import subprocess
from typing import Any, Dict, Optional


def marker_frames(path: str, rgb: tuple, min_pixels: int = 4096) -> Optional[Dict[str, Any]]:
    """返回该颜色像素数最多的帧 {frame, pixels}；没有一帧达到阈值时返回 None。"""
    r, g, b = rgb
    expr = f"if(eq(r(X,Y),{r})*eq(g(X,Y),{g})*eq(b(X,Y),{b}),255,0)"
    proc = subprocess.run(
        ["ffmpeg", "-v", "error", "-i", path, "-vf",
         f"format=rgb24,lutrgb=r='{expr}':g=0:b=0,"
         "signalstats,metadata=print:key=lavfi.signalstats.YAVG", "-f", "null", "-"],
        capture_output=True, text=True, timeout=240,
    )
    if proc.returncode != 0:
        return None
    best: Optional[Dict[str, Any]] = None
    frame = -1
    for line in (proc.stdout or "").splitlines():
        match = re.search(r"frame:(\d+)", line)
        if match:
            frame = int(match.group(1))
            continue
        match = re.search(r"YAVG=([0-9.]+)", line)
        if match and frame >= 0:
            # lutrgb 把命中像素置成 (255,0,0)：YAVG ≈ 0.299 × 255 × 占比
            pixels = int(round(float(match.group(1)) / 0.299))
            if best is None or pixels > best["pixels"]:
                best = {"frame": frame, "pixels": pixels}
    if best is None or best["pixels"] < min_pixels:
        return None
    return best


def parse_rgb(value: str) -> Optional[tuple]:
    raw = (value or "").strip()
    if not raw:
        return None
    parts = raw.replace("#", "").split(",")
    if len(parts) == 1 and len(parts[0]) == 6:
        raw = parts[0]
        return tuple(int(raw[i:i + 2], 16) for i in (0, 2, 4))
    if len(parts) != 3:
        raise ValueError("已知内容颜色应为 R,G,B 或 6 位十六进制")
    return tuple(int(p) for p in parts)
