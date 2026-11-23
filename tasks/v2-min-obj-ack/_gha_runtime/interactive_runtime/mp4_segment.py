"""纯标准库 MP4 关键帧切分（桌面录像分段用）。

为什么不直接用 ffmpeg 的 segment muxer：

- `-segment_time N -force_key_frames expr:gte(t,n_forced*N)` 会按"每段内重新计时"的
  PTS 评估表达式，切出来的每段内部又会被 2s 一断（实测 10s 素材 → 605 个碎段）。
- 只给 `-segment_time N` 时流复制只在关键帧处切，x11grab 的关键帧间隔决定了段长，
  5s 的段会变成 8~10s，且无法控制。

这里直接解析采集文件的 box 树（mvhd/tkhd/mdhd、stts、stsz、stsc、stco、stss），
在关键帧索引上按 segment_seconds 选切点，再用 `-c copy` 等价的方式重写每个片段的
moov（时间表按片段截取、stco 指向新 mdat 的相对绝对偏移）与 mdat 字节。
不解码、不重编码，每段都是独立可 seek 的普通 MP4。只支持单视频轨。
"""

from __future__ import annotations

import os
import struct
from typing import List, Optional, Tuple

CONTAINER = {b"moov", b"trak", b"mdia", b"minf", b"stbl"}


class MP4Error(RuntimeError):
    pass


# ---------------------------------------------------------------- box 读取

def _iter_boxes(buf: bytes, start: int, end: int):
    pos = start
    while pos + 8 <= end:
        size, typ = struct.unpack(">I4s", buf[pos:pos + 8])
        head = 8
        if size == 1:
            size = struct.unpack(">Q", buf[pos + 8:pos + 16])[0]
            head = 16
        elif size == 0:
            size = end - pos
        if size < head:
            break
        yield typ, pos, head, size
        pos += size


def _find(buf: bytes, start: int, end: int, typ: bytes) -> Tuple[int, int, int]:
    for t, pos, head, size in _iter_boxes(buf, start, end):
        if t == typ:
            return pos, head, size
    raise MP4Error(f"缺少 box {typ!r}")


def _find_path(buf: bytes, start: int, end: int, path) -> Tuple[int, int, int]:
    pos, head, size = start, 0, end - start
    for typ in path:
        pos, head, size = _find(buf, pos + head, pos + size, typ)
    return pos, head, size


def _video_trak(buf: bytes, start: int, end: int) -> Tuple[int, int, int]:
    for typ, tpos, thead, tsize in _iter_boxes(buf, start, end):
        if typ != b"trak":
            continue
        try:
            mdia = _find(buf, tpos + thead, tpos + tsize, b"mdia")
            hdlr = _find(buf, mdia[0] + mdia[1], mdia[0] + mdia[2], b"hdlr")
        except MP4Error:
            continue
        # hdlr: version+flags(4) pre_defined(4) handler_type(4)
        if buf[hdlr[0] + hdlr[1] + 8:hdlr[0] + hdlr[1] + 12] == b"vide":
            return tpos, thead, tsize
    raise MP4Error("没有视频 trak")


def _in_trak(buf: bytes, trak: Tuple[int, int, int], path) -> Tuple[int, int, int]:
    pos, head, size = trak
    for typ in path:
        pos, head, size = _find(buf, pos + head, pos + size, typ)
    return pos, head, size


def _box(typ: bytes, payload: bytes) -> bytes:
    return struct.pack(">I4s", len(payload) + 8, typ) + payload


def _table_box(typ: bytes, version: int, entries: List[bytes]) -> bytes:
    body = struct.pack(">I", len(entries)) + b"".join(entries)
    return _box(typ, struct.pack(">B3s", version, b"\x00\x00\x00") + body)


class Movie:
    """单视频轨 MP4 的时间表与样本位置。"""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as f:
            self.raw = f.read()
        buf = self.raw
        self.moov = _find(buf, 0, len(buf), b"moov")
        self.mdat = _find(buf, 0, len(buf), b"mdat")
        moov_pos, moov_head, moov_size = self.moov
        self.moov_bytes = buf[moov_pos:moov_pos + moov_size]

        mvhd_pos, mvhd_head, mvhd_size = _find(buf, moov_pos + moov_head, moov_pos + moov_size, b"mvhd")
        mv = buf[mvhd_pos + mvhd_head:mvhd_pos + mvhd_size]
        if mv[0] == 0:
            self.movie_timescale = struct.unpack(">I", mv[12:16])[0]
        else:
            self.movie_timescale = struct.unpack(">I", mv[20:24])[0]

        self.trak = _video_trak(buf, moov_pos + moov_head, moov_pos + moov_size)
        mdhd = _in_trak(buf, self.trak, (b"mdia", b"mdhd"))
        mh = buf[mdhd[0] + mdhd[1]:mdhd[0] + mdhd[2]]
        self.media_timescale = struct.unpack(">I", mh[12:16])[0] if mh[0] == 0 else \
            struct.unpack(">I", mh[20:24])[0]
        stbl = _in_trak(buf, self.trak, (b"mdia", b"minf", b"stbl"))
        self.stbl_start, self.stbl_head, self.stbl_size = stbl
        self.stbl_end = stbl[0] + stbl[2]
        self.children = list(_iter_boxes(buf, stbl[0] + stbl[1], self.stbl_end))

        self.stts = self._table(b"stts", 8)
        self.stsc = self._table(b"stsc", 12)
        self.stsz = self._sizes()
        self.stco = self._co()
        try:
            self.stss = self._table(b"stss", 4)
        except MP4Error:
            self.stss = None

    # ---- 表
    def _raw_child(self, typ: bytes) -> bytes:
        for t, pos, head, size in self.children:
            if t == typ:
                return self.raw[pos + head:pos + size]
        raise MP4Error(f"stbl 缺少 {typ!r}")

    def _table(self, typ: bytes, entry: int) -> List[bytes]:
        body = self._raw_child(typ)
        n = struct.unpack(">I", body[4:8])[0]
        return [body[8 + i * entry:8 + (i + 1) * entry] for i in range(n)]

    def _sizes(self) -> List[int]:
        body = self._raw_child(b"stsz")
        default, n = struct.unpack(">II", body[4:12])
        if default:
            return [default] * n
        data = body[12:]
        return [struct.unpack(">I", data[i * 4:(i + 1) * 4])[0] for i in range(n)]

    def _co(self) -> List[int]:
        for typ, entry in ((b"stco", 4), (b"co64", 8)):
            try:
                rows = self._table(typ, entry)
                return [struct.unpack(">I" if entry == 4 else ">Q", r)[0] for r in rows]
            except MP4Error:
                continue
        raise MP4Error("缺少 stco/co64")

    # ---- 样本
    def offsets(self) -> List[int]:
        if not hasattr(self, "_offsets"):
            offs: List[int] = []
            idx = 0
            for i, row in enumerate(self.stsc):
                first, per, _ = struct.unpack(">III", row)
                last = struct.unpack(">I", self.stsc[i + 1][:4])[0] if i + 1 < len(self.stsc) \
                    else len(self.stco) + 1
                for chunk in range(first, last):
                    base = self.stco[chunk - 1]
                    for _ in range(per):
                        if idx >= len(self.stsz):
                            break
                        offs.append(base)
                        base += self.stsz[idx]
                        idx += 1
            self._offsets = offs
        return self._offsets

    def durations(self) -> List[int]:
        out: List[int] = []
        for row in self.stts:
            count, delta = struct.unpack(">II", row)
            out.extend([delta] * count)
        return out

    def keyframes(self) -> List[int]:
        if self.stss is None:
            return list(range(len(self.stsz)))
        return [struct.unpack(">I", r)[0] - 1 for r in self.stss]

    def _decode_order_samples(self) -> List[int]:
        """样本在文件中的物理顺序（stco/stsc 顺序）→ 解码序号。

        带 B 帧的 H.264 里 stts 按显示顺序排列样本，而 mdat 里的样本是按解码顺序
        排的。stss 给的是 1-based 的【解码】序号，直接拿它去索引 stts 会错位。
        用一帧延迟的 dts(i)=min(pts(i), pts(i+1)) 把显示顺序还原成解码顺序。
        """
        starts = []
        t = 0
        for d in self.durations():
            starts.append(t)
            t += d
        order = list(range(len(starts)))
        order.sort(key=lambda i: (starts[i], i))
        rank = [0] * len(starts)
        for pos, idx in enumerate(order):
            rank[idx] = pos
        return rank

    def cut_points(self, seconds: int) -> List[int]:
        """返回切点样本下标（显示顺序索引，含 0）。"""
        dur = self.durations()
        starts = []
        t = 0
        for d in dur:
            starts.append(t)
            t += d
        rank = self._decode_order_samples()
        keys_display = sorted({rank[k] for k in self.keyframes() if 0 <= k < len(rank)})
        total_seconds = t / self.media_timescale if self.media_timescale else 0
        cuts = [0]
        target = seconds
        ki = 0
        while target < total_seconds - 1e-6 and ki < len(keys_display):
            while ki < len(keys_display) and starts[keys_display[ki]] / self.media_timescale < target - 1e-6:
                ki += 1
            if ki >= len(keys_display):
                break
            idx = keys_display[ki]
            if idx > cuts[-1]:
                cuts.append(idx)
                target = starts[idx] / self.media_timescale + seconds
            else:
                ki += 1
        return cuts

    # ---- 写片段
    def write_segment(self, out_path: str, start: int, end: int) -> None:
        dur = self.durations()[start:end]
        # 物理顺序 = stco/stsc 顺序（解码顺序）；按显示索引建出的片段需要重排样本
        rank = self._decode_order_samples()
        display_idx = list(range(start, end))
        ordered = sorted(display_idx, key=lambda i: rank[i])
        offs_all = self.offsets()
        chunks = []
        prev_end = None
        for i in ordered:
            if prev_end != offs_all[i]:
                chunks.append([])
            chunks[-1].append(i)
            prev_end = offs_all[i] + self.stsz[i]
        payload = bytearray()
        chunk_starts = []
        for chunk in chunks:
            chunk_starts.append(len(payload))
            for i in chunk:
                payload += self.raw[offs_all[i]:offs_all[i] + self.stsz[i]]
        ordered_sizes = [self.stsz[i] for i in ordered]
        media_dur = sum(dur)  # 显示顺序时长之和 = 片段时长
        movie_dur = int(round(media_dur * self.movie_timescale / max(1, self.media_timescale)))

        # chunk 沿用源文件的连续区间（通常每样本一个），stsc 描述 chunk 内样本数
        stco_entries = [struct.pack(">I", off) for off in chunk_starts]
        stsc_rows = []
        for n, chunk in enumerate(chunks):
            stsc_rows.append(struct.pack(">III", n + 1, len(chunk), 1))

        def stbl_bytes(mdat_offset: int) -> bytes:
            parts = []
            for typ, cpos, chead, csize in self.children:
                raw = self.raw[cpos + chead:cpos + csize]
                if typ == b"stsd":
                    parts.append(_box(b"stsd", raw))
                elif typ == b"stts":
                    parts.append(_table_box(b"stts", 0, [struct.pack(">II", 1, media_dur)]))
                elif typ == b"stsc":
                    parts.append(_table_box(b"stsc", 0, stsc_rows))
                elif typ == b"stsz":
                    parts.append(_box(b"stsz", struct.pack(">B3sII", 0, b"\x00\x00\x00", 0,
                                                           len(ordered_sizes)) +
                                      b"".join(struct.pack(">I", s) for s in ordered_sizes)))
                elif typ in (b"stco", b"co64"):
                    parts.append(_table_box(b"stco", 0, [
                        struct.pack(">I", mdat_offset + struct.unpack(">I", e)[0]) for e in stco_entries]))
                elif typ == b"stss":
                    # stss 是 1-based 的【解码顺序】序号；段内首个样本一定在 cuts 上
                    pos_of = {i: n for n, i in enumerate(ordered)}
                    keys = sorted({pos_of[k] + 1 for k in self.keyframes()
                                   if start <= k < end and pos_of.get(k, 0) > 0})
                    if keys:
                        parts.append(_table_box(b"stss", 0, [struct.pack(">I", k) for k in keys]))
                else:
                    parts.append(_box(typ, raw))
            return _box(b"stbl", b"".join(parts))

        def moov_bytes(mdat_offset: int) -> bytes:
            new_stbl = stbl_bytes(mdat_offset)
            # moov_bytes 保留 box 头（8 字节），stbl 的偏移要一并减掉
            rel = self.stbl_start - self.moov[0] - self.moov[1]
            pre = self.moov_bytes[:rel]
            post = self.moov_bytes[rel + self.stbl_size:]
            return _set_durations(pre + new_stbl + post, movie_dur, media_dur)

        dummy = moov_bytes(0)
        ftyp = self._ftyp()
        mdat_offset = len(ftyp) + len(dummy) + 8
        moov = moov_bytes(mdat_offset)
        with open(out_path, "wb") as f:
            f.write(ftyp)
            f.write(moov)
            f.write(struct.pack(">I4s", len(payload) + 8, b"mdat"))
            f.write(payload)

    def _ftyp(self) -> bytes:
        for typ, pos, head, size in _iter_boxes(self.raw, 0, len(self.raw)):
            if typ == b"ftyp":
                return self.raw[pos:pos + size]
        return _box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2avc1mp41")


def _set_durations(moov: bytes, movie_dur: int, media_dur: int) -> bytes:
    """mvhd/tkhd/mdhd 的 duration 改成片段时长（按各自 version 写 32/64 位）。"""
    out = bytearray(moov)
    pos = 0
    while pos + 8 <= len(out):
        size, typ = struct.unpack(">I4s", out[pos:pos + 8])
        if size < 8:
            break
        body = pos + 8
        if typ in (b"moov", b"trak", b"mdia"):
            # 递归处理子 box
            patched = _set_durations(bytes(out[body:pos + size]), movie_dur, media_dur)
            out[body:pos + size] = patched
        elif typ == b"mvhd":
            version = out[body]
            if version == 0:
                struct.pack_into(">I", out, body + 16, min(movie_dur, 0xFFFFFFFF))
            else:
                struct.pack_into(">Q", out, body + 24, movie_dur)
        elif typ == b"tkhd":
            version = out[body]
            if version == 0:
                struct.pack_into(">I", out, body + 20, min(movie_dur, 0xFFFFFFFF))
            else:
                struct.pack_into(">Q", out, body + 28, movie_dur)
        elif typ == b"mdhd":
            version = out[body]
            if version == 0:
                struct.pack_into(">I", out, body + 16, min(media_dur, 0xFFFFFFFF))
            else:
                struct.pack_into(">Q", out, body + 24, media_dur)
        pos += size
    return bytes(out)


def split_mp4(src: str, pattern: str, segment_seconds: int) -> List[str]:
    """把 src 按关键帧切成 segment_seconds 左右的片段；pattern 需含 %03d。"""
    movie = Movie(src)
    cuts = movie.cut_points(max(1, segment_seconds))
    bounds = cuts + [len(movie.stsz)]
    produced: List[str] = []
    for i in range(len(bounds) - 1):
        start, end = bounds[i], bounds[i + 1]
        if end <= start:
            continue
        path = pattern % i
        movie.write_segment(path, start, end)
        produced.append(path)
    return produced


if __name__ == "__main__":  # 手工验证：python -m interactive_runtime.mp4_segment in.mp4 out-%03d.mp4 5
    import sys
    print(split_mp4(sys.argv[1], sys.argv[2], int(sys.argv[3])))
