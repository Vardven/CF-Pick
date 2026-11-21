# -*- coding: utf-8 -*-
"""生成 CF-Pick.ico（纯标准库，无 PIL）。"""

import math
import struct
import zlib

BASE = 1024
SIZES = [256, 128, 64, 48, 32, 16]


def smooth(e0, e1, x):
    if e1 == e0:
        return 0.0 if x < e0 else 1.0
    t = (x - e0) / (e1 - e0)
    t = 0.0 if t < 0 else (1.0 if t > 1 else t)
    return t * t * (3 - 2 * t)


def render_base():
    W = BASE
    cx = cy = W / 2.0
    half = W * 0.5
    rad = W * 0.235
    # 圆角矩形到中心的“距离”
    ix, iy = half - rad, half - rad
    ring_out = W * 0.300
    ring_in = W * 0.300 - W * 0.058
    dot_r = W * 0.088

    # 预乘 alpha 的 RGBA
    buf = bytearray(W * W * 4)
    for y in range(W):
        dy = abs(y + 0.5 - cy) - iy
        dy = dy if dy > 0 else 0.0
        row = y * W * 4
        for x in range(W):
            dx = abs(x + 0.5 - cx) - ix
            dx = dx if dx > 0 else 0.0
            drect = math.hypot(dx, dy)
            a = 1.0 - smooth(rad - 1.5, rad + 1.5, drect)
            if a <= 0.002:
                continue
            t = (x + y) / (2.0 * W)
            cr = 30 + (150 - 30) * t
            cg = 198 + (140 - 198) * t
            cb = 232 + (250 - 232) * t
            # 左上角高光
            hl = max(0.0, 1.0 - math.hypot(x - W * 0.26, y - W * 0.18) / (W * 0.62))
            cr += 26 * hl
            cg += 18 * hl
            cb += 8 * hl
            # 右下角压暗
            sh = max(0.0, 1.0 - math.hypot(x - W * 0.82, y - W * 0.92) / (W * 0.7))
            cr -= 22 * sh
            cg -= 34 * sh
            cb -= 10 * sh

            d = math.hypot(x + 0.5 - cx, y + 0.5 - cy)
            ring = smooth(ring_in - 1.6, ring_in + 1.6, d) * (1.0 - smooth(ring_out - 1.6, ring_out + 1.6, d))
            dot = 1.0 - smooth(dot_r - 1.6, dot_r + 1.6, d)
            w = min(1.0, ring * 1.0 + dot * 1.0)
            if w > 0:
                cr = cr * (1 - w) + 255 * w
                cg = cg * (1 - w) + 255 * w
                cb = cb * (1 - w) + 255 * w

            i = row + x * 4
            buf[i] = 0 if cr < 0 else (255 if cr > 255 else int(cr))
            buf[i + 1] = 0 if cg < 0 else (255 if cg > 255 else int(cg))
            buf[i + 2] = 0 if cb < 0 else (255 if cb > 255 else int(cb))
            buf[i + 3] = int(a * 255)
    return buf


def downscale(buf, W, size):
    k = W // size
    out = bytearray(size * size * 4)
    for y in range(size):
        for x in range(size):
            r = g = b = a = 0.0
            for yy in range(k):
                base = ((y * k + yy) * W + x * k) * 4
                for xx in range(k):
                    i = base + xx * 4
                    pa = buf[i + 3] / 255.0
                    r += buf[i] * pa
                    g += buf[i + 1] * pa
                    b += buf[i + 2] * pa
                    a += pa
            n = k * k
            av = a / n
            o = (y * size + x) * 4
            if av <= 0.001:
                continue
            out[o] = min(255, int(r / a))
            out[o + 1] = min(255, int(g / a))
            out[o + 2] = min(255, int(b / a))
            out[o + 3] = int(av * 255)
    return out


def png_bytes(size, rgba):
    rows = []
    for y in range(size):
        rows.append(bytes(rgba[y * size * 4:(y + 1) * size * 4]))

    def chunk(tag, data):
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + r for r in rows)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def main():
    print("rendering %dx%d ..." % (BASE, BASE))
    buf = render_base()
    pngs = []
    for s in SIZES:
        rgba = downscale(buf, BASE, s)
        pngs.append((s, png_bytes(s, rgba)))
        print("  size", s, "ok")
    with open("preview512.png", "wb") as f:
        f.write(png_bytes(256, downscale(buf, BASE, 256)))

    n = len(pngs)
    off = 6 + 16 * n
    head = struct.pack("<HHH", 0, 1, n)
    dirs = b""
    for s, d in pngs:
        dirs += struct.pack("<BBBBHHII", 0 if s >= 256 else s, 0 if s >= 256 else s, 0, 0, 1, 32, len(d), off)
        off += len(d)
    with open("icon.ico", "wb") as f:
        f.write(head + dirs + b"".join(d for _, d in pngs))
    print("icon.ico written")


if __name__ == "__main__":
    main()
