"""桌面与浏览器录像录制器（含分段录像与隐私暂停）。

遵循《2.0 迭代.md》第十四章「浏览器录像、桌面录像和 Trace」。
特性：
- FFmpeg X11 Grab 虚拟桌面视频采集；
- 按时长（如 60s）分段切分录像，已完成片段提前回传；
- 隐私暂停/恢复接口，在密码输入与 2FA 阶段暂停录像。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import List, Optional


class DesktopRecorder:
    """桌面视频录制器"""

    def __init__(
        self,
        output_dir: str,
        display: str = ":99",
        segment_seconds: int = 60,
        resolution: str = "1280x800",
        fps: int = 10,
        force_mock: bool = False,
    ):
        self.output_dir = output_dir
        self.display = display
        self.segment_seconds = segment_seconds
        self.resolution = resolution
        self.fps = fps
        self.force_mock = force_mock

        self._proc: Optional[subprocess.Popen] = None
        self._is_recording: bool = False
        self._is_paused: bool = False
        self._segment_files: List[str] = []
        os.makedirs(self.output_dir, exist_ok=True)

    @property
    def is_recording(self) -> bool:
        return self._is_recording

    @property
    def is_paused(self) -> bool:
        return self._is_paused

    def start(self) -> bool:
        """开始录制桌面"""
        if self._is_recording:
            return True

        if self.force_mock:
            self._is_recording = True
            dummy = os.path.join(self.output_dir, "segment-000.mp4")
            with open(dummy, "wb") as f:
                f.write(b"\x00\x00\x00\x20ftypmp42\x00\x00\x00\x00isommp42")
            self._segment_files.append(dummy)
            return True
        if not shutil.which("ffmpeg"):
            return False

        segment_pattern = os.path.join(self.output_dir, "segment-%03d.mp4")
        env = os.environ.copy()
        env["DISPLAY"] = self.display

        cmd = [
            "ffmpeg",
            "-y",
            "-f", "x11grab",
            "-video_size", self.resolution,
            "-framerate", str(self.fps),
            "-i", self.display,
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-f", "segment",
            "-segment_time", str(self.segment_seconds),
            "-reset_timestamps", "1",
            segment_pattern,
        ]

        try:
            self._proc = subprocess.Popen(
                cmd,
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._is_recording = True
            return True
        except Exception:
            return False

    def pause(self) -> None:
        """暂停录屏（隐私模式）"""
        if not self._is_recording or self._is_paused:
            return
        self._is_paused = True
        if self._proc:
            try:
                # 发送 SIGSTOP 挂起
                import signal
                self._proc.send_signal(signal.SIGSTOP)
            except Exception:
                pass

    def resume(self) -> None:
        """恢复录屏"""
        if not self._is_recording or not self._is_paused:
            return
        self._is_paused = False
        if self._proc:
            try:
                import signal
                self._proc.send_signal(signal.SIGCONT)
            except Exception:
                pass

    def stop(self) -> List[str]:
        """停止录屏并返回生成的片段文件清单"""
        if not self._is_recording:
            return self._segment_files

        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

        self._is_recording = False
        self._is_paused = False

        # 扫描产出片段
        segments = []
        if os.path.isdir(self.output_dir):
            for fn in sorted(os.listdir(self.output_dir)):
                if fn.startswith("segment-") and fn.endswith(".mp4"):
                    segments.append(os.path.join(self.output_dir, fn))

        self._segment_files = segments
        return segments
