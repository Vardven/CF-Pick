#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生成 PyInstaller 启动画面 splash.png（深色卡片 + 环形 logo + 标题）。

PyInstaller 的 splash 用 Tk 渲染，会在 exe 解压阶段就显示出来，
所以双击后立刻有反馈，不会让人以为没点着而反复双击。
"""

import os

from PIL import Image, ImageDraw, ImageFont

W, H = 600, 340
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "splash.png")

BG = (11, 14, 24)
BORDER = (30, 38, 54)
FG = (232, 236, 244)
MUTED = (137, 146, 166)
ACCENT = (125, 211, 252)

FONT_CN = "C:/Windows/Fonts/msyh.ttc"
FONT_EN = "C:/Windows/Fonts/segoeui.ttf"
FONT_EN_B = "C:/Windows/Fonts/segoeuib.ttf"


def font(path, size):
    try:
        return ImageFont.truetype(path, size)
    except OSError:
        return ImageFont.load_default()


img = Image.new("RGBA", (W, H), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# 卡片
d.rounded_rectangle([0, 0, W - 1, H - 1], radius=18, fill=BG + (255,))
d.rounded_rectangle([0, 0, W - 1, H - 1], radius=18, outline=BORDER + (255,), width=1)

# 环形 logo（与应用图标一致：圆环 + 中心点）
cx, cy, r = W // 2, 118, 40
d.ellipse([cx - r, cy - r, cx + r, cy + r], outline=FG + (255,), width=5)
d.ellipse([cx - 7, cy - 7, cx + 7, cy + 7], fill=FG + (255,))

# 标题与副标题
f_title = font(FONT_EN_B, 28)
f_sub = font(FONT_CN, 14)
d.text((W // 2, 186), "CF-Pick", font=f_title, fill=FG + (255,), anchor="mm")
d.text((W // 2, 216), "Cloudflare 入口优选测速台", font=f_sub, fill=MUTED + (255,), anchor="mm")

# 进度条（静态 34%，配合动效文字传达"在启动"）
bw, bh = 240, 4
bx, by = (W - bw) // 2, 262
d.rounded_rectangle([bx, by, bx + bw, by + bh], radius=2, fill=(26, 33, 48, 255))
d.rounded_rectangle([bx, by, bx + int(bw * 0.34), by + bh], radius=2, fill=ACCENT + (255,))

# 底部提示（PyInstaller 会把 update_text 叠在窗口底部，这里留白不冲突）
f_tip = font(FONT_CN, 12)
d.text((W // 2, 300), "首次启动需解压，约 1–3 秒", font=f_tip, fill=(104, 113, 130, 255), anchor="mm")

img.save(OUT)
print("saved", OUT, img.size)
