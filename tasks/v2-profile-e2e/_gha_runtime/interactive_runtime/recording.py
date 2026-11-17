"""桌面与浏览器录像录制器（含分段录像与隐私暂停）。

遵循《2.0 迭代.md》第十四章「浏览器录像、桌面录像和 Trace」。
特性：
- FFmpeg X11 Grab 虚拟桌面视频采集（单次采集写入 recording.mp4）；
- 收尾时（stop() / checkpoint）按关键帧切成 segment_seconds 片段，每段独立可解析；
- 隐私暂停/恢复接口，在密码输入与 2FA 阶段暂停录像。
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import List, Optional

from .mp4_segment import split_mp4


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
        self.last_error = ""

        self._proc: Optional[subprocess.Popen] = None
        self._is_recording: bool = False
        self._is_paused: bool = False
        self._segment_files: List[str] = []
        self._claimed: set = set()
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
            self.last_error = "ffmpeg 不可用"
            return False

        env = os.environ.copy()
        env["DISPLAY"] = self.display

        # 一次性录到文件末尾，不在录制中运行时分片：
        # - segment muxer 用默认的 PTS 等长切分，配合 -reset_timestamps 1 会把每段
        #   最长撑到 2*segment_time/3 以上，5s 段要 9s 左右才落盘；而且分片后的 .mp4
        #   要等下一次切分才会把上一段的 moov 写完。"录制中+分段"因此无法保证"每个
        #   已过时长都有完整、可 seek 的片段"。
        # - stop() 用 SIGINT 让 ffmpeg 正常收尾，再把整段按 reset_timestamps 0 切成
        #   真正的 segment_seconds 段，每段都能被 ffprobe/mp4 解析。
        cmd = [
            "ffmpeg",
            "-y",
            "-f", "x11grab",
            "-video_size", self.resolution,
            "-framerate", str(self.fps),
            "-i", self.display,
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-pix_fmt", "yuv420p",
            # 2 秒一个关键帧，且关掉场景切换关键帧：切点稳定、段长可预期
            "-force_key_frames", f"expr:gte(t,n_forced*2)",
            "-x264-params", "scenecut=0",
            os.path.join(self.output_dir, "recording.mp4"),
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
        except Exception as exc:
            self.last_error = f"{type(exc).__name__}: {str(exc)[:200]}"
            return False

    def completed_segments(self) -> List[str]:
        """返回已落盘且非空的片段，供运行中分段回传；不把进程存活当成文件有效。"""
        if not os.path.isdir(self.output_dir):
            return []
        return [
            os.path.join(self.output_dir, fn)
            for fn in sorted(os.listdir(self.output_dir))
            if fn.startswith("segment-") and fn.endswith(".mp4")
            and os.path.getsize(os.path.join(self.output_dir, fn)) > 0
        ]

    def pending_segments(self) -> List[str]:
        """尚未认领过的非空片段：检查点多走一次时不再把同一段录像登记第二遍。"""
        fresh = [p for p in self.completed_segments()
                 if os.path.realpath(p) not in self._claimed]
        self._claimed.update(os.path.realpath(p) for p in fresh)
        return fresh

    def unfinished_segment(self) -> str:
        """仍在写入中的单次采集文件（回传前必须先 finalize）。"""
        path = os.path.join(self.output_dir, "recording.mp4")
        return path if os.path.isfile(path) and os.path.getsize(path) > 0 else ""

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
        """停止录屏，按 segment_seconds 切分并返回片段文件清单"""
        if not self._is_recording:
            return self._segment_files

        # SIGINT 是 ffmpeg 的"优雅停止"：写完尾部帧与 moov 再退出。SIGTERM/SIGKILL
        # 会留下没有 moov 的 mp4，ffprobe 读不了。
        if self._proc:
            try:
                if self._is_paused:
                    import signal
                    self._proc.send_signal(signal.SIGCONT)
                self._proc.send_signal(signal.SIGINT)
                self._proc.wait(timeout=15)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

        self._is_recording = False
        self._is_paused = False
        self._finalize_segments()

        # 扫描产出片段
        segments = []
        if os.path.isdir(self.output_dir):
            for fn in sorted(os.listdir(self.output_dir)):
                if fn.startswith("segment-") and fn.endswith(".mp4"):
                    segments.append(os.path.join(self.output_dir, fn))

        self._segment_files = segments
        if not segments:
            self.last_error = "FFmpeg 未生成有效视频片段"
        return segments

    def finalize_for_checkpoint(self) -> List[str]:
        """让"当前已录内容"成为可回传的完整片段，录制继续。

        用 SIGINT 把这次采集正常收尾（写 moov），切成若干段后立刻以同一参数重启，
        后续画面进入新的一次采集。返回本次新落盘的片段。
        """
        if not self._is_recording or self._proc is None:
            return []
        before = set(self.completed_segments())
        if self._is_paused:
            code = self._stop_proc(grace=2.0)
        else:
            code = self._stop_proc(grace=15.0)
        self._proc = None
        self._is_recording = False
        self._finalize_segments()
        if not self.start():
            raise RuntimeError(f"录像重启失败：{self.last_error}")
        self._is_paused = False
        return [p for p in self.completed_segments() if p not in before]

    def _stop_proc(self, grace: float) -> Optional[int]:
        proc = self._proc
        if proc is None:
            return None
        try:
            import signal
            if self._is_paused:
                proc.send_signal(signal.SIGCONT)
            proc.send_signal(signal.SIGINT)
            return proc.wait(timeout=grace)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
            return None

    def _finalize_segments(self) -> None:
        """把单次采集的 recording.mp4 按关键帧切成 segment_seconds 片段。

        ffmpeg 的 segment muxer 按"每段内重新计时"的 PTS 评估切点，强制关键帧时会把
        整段切碎；这里用 mp4_segment 在关键帧索引上切（流复制，不重编码），每段都是
        独立可 seek 的普通 MP4。
        """
        src = os.path.join(self.output_dir, "recording.mp4")
        if not os.path.isfile(src) or os.path.getsize(src) == 0:
            return
        base = int(time.time() * 1000)
        pattern = os.path.join(self.output_dir, f"segment-{base}-%03d.mp4")
        try:
            produced = split_mp4(src, pattern, max(1, self.segment_seconds))
        except Exception as exc:
            self.last_error = f"分段失败：{type(exc).__name__}: {str(exc)[:200]}"
            return
        if not produced:
            self.last_error = "分段失败：没有产出片段"
            return
        try:
            os.remove(src)
        except OSError:
            pass
