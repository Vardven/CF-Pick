#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 PyInstaller 启动图 splash.png。

双击 exe 后前 1~2 秒是解压阶段，只有这张静态图能看；Python 一起来就换成
cfpick.py 里自绘的启动窗（_spl_* 那一组）。所以这张图必须和自绘窗口的
第一帧对齐：一样的尺寸、一样的竖向渐变底、一样的 logo 与文字位置，
换窗那一刻才看不出接缝，后面只有进度条和文案接着动。

改这里的时候记得同步 cfpick.py 的 SPL_W / SPL_H 和 _spl_text 的坐标。
"""

import os

from PIL import Image, ImageDraw, ImageFont

W, H, R = 600, 262, 16
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "splash.png")

BG_TOP = (17, 22, 36)
BG_BOT = (8, 11, 19)
TRACK = (32, 40, 56)
CYAN = (34, 211, 238)
INDIGO = (129, 140, 248)
VIOLET = (167, 139, 250)
FG = (242, 245, 251)
SUB = (142, 153, 175)
TIP = (78, 90, 112)
PCT = (103, 232, 249)

FONT_CN = "C:/Windows/Fonts/msyh.ttc"
FONT_CN_B = "C:/Windows/Fonts/msyhbd.ttc"


def font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.load_default()


img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# 1) 竖向渐变底（逐行画，和 _spl_bg 的算法一致）
for y in range(H):
    k = y / max(1, H - 1)
    d.line([(0, y), (W, y)], fill=tuple(
        int(BG_BOT[i] + (BG_TOP[i] - BG_BOT[i]) * (1 - k)) for i in range(3)) + (255,))

# 2) 圆角：四角裁成透明（16px，和窗口的 alpha 表一致）
mask = Image.new("L", (W, H), 0)
ImageDraw.Draw(mask).rounded_rectangle([0, 0, W - 1, H - 1], radius=R, fill=255)
img.putalpha(mask)

# 3) logo：圆环 + 中心点
cx, cy, r = 56, 76, 21
d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=(8, 11, 18, 255),
          outline=(232, 236, 244, 255), width=4)
d.ellipse([cx - 5, cy - 5, cx + 5, cy + 5], fill=(232, 236, 244, 255))

# 4) 文字（坐标 = 自绘版按 1x 缩放后的位置）
d.text((96, 57), "CF-Pick", font=font(FONT_CN_B, 26), fill=FG + (255,), anchor="lm")
d.text((97, 94), "Cloudflare 入口优选测速台", font=font(FONT_CN, 13), fill=SUB + (255,), anchor="lm")

# 5) 进度条：底槽 + 4% 起始填充（自绘窗口从这儿接着涨）
bx0, bx1, by, bh = 34, 566, 152, 5
d.rounded_rectangle([bx0, by, bx1, by + bh - 1], radius=bh // 2 + 1, fill=TRACK + (255,))
fillw = int((bx1 - bx0) * 0.04)
for x in range(bx0, bx0 + fillw):
    t = (x - bx0) / max(1, bx1 - bx0)
    if t < 0.55:
        u = t / 0.55
        c = tuple(int(CYAN[i] + (INDIGO[i] - CYAN[i]) * u) for i in range(3))
    else:
        u = (t - 0.55) / 0.45
        c = tuple(int(INDIGO[i] + (VIOLET[i] - INDIGO[i]) * u) for i in range(3))
    d.line([(x, by), (x, by + bh - 1)], fill=c + (255,))

d.text((34, 180), "正在解压运行组件…", font=font(FONT_CN, 13), fill=SUB + (255,), anchor="lm")
d.text((566, 180), "4%", font=font(FONT_CN, 13), fill=PCT + (255,), anchor="rm")
d.text((34, 213), "本地并发测速 · 结果只留在本机", font=font(FONT_CN, 11), fill=TIP + (255,), anchor="lm")

img.save(OUT)
print("saved", OUT, img.size)
