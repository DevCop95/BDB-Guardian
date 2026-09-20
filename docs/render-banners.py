"""Render repo banners from real capture logs (terminal-style PNGs)."""
import os
from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS = os.path.join(ROOT, "docs")
CAP = os.path.join(ROOT, "captures")
FONT_PATH = r"C:\Windows\Fonts\consola.ttf"

BG = (13, 17, 23)
BAR = (22, 27, 34)
FG = (201, 209, 217)
RED = (255, 123, 114)
GREEN = (126, 226, 160)
GRAY = (139, 148, 158)
CYAN = (121, 192, 255)
YELLOW = (226, 200, 126)
DOT_R, DOT_Y, DOT_G = (255, 95, 86), (255, 189, 46), (39, 201, 63)


def font(size, bold=False):
    # Consolas has no separate bold file on stock Windows; emulate with stroke.
    return ImageFont.truetype(FONT_PATH, size)


def color_for(line):
    s = line.strip()
    if s.startswith("[High]"):
        return RED
    if s.startswith("[Info"):
        return GRAY
    if s.startswith("-----"):
        return CYAN
    if s.startswith("[*]"):
        return FG
    if "VERDICT: CRITICAL" in s:
        return RED
    if "VERDICT: CLEAN" in s:
        return GREEN
    if s.startswith("==") or s.startswith(" BDB-"):
        return CYAN
    return FG


def render_terminal(lines, title, out_path, font_size=17):
    fnt = font(font_size)
    pad = 22
    tmp = Image.new("RGB", (10, 10))
    d0 = ImageDraw.Draw(tmp)
    maxw = 0
    for ln in lines:
        bb = d0.textbbox((0, 0), ln, font=fnt)
        maxw = max(maxw, bb[2] - bb[0])
    lh = font_size + 9
    chrome = 52
    W = maxw + pad * 2 + 8
    H = chrome + lh * len(lines) + pad
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, W - 1, H - 1], radius=14, outline=(48, 54, 61), width=2)
    d.line([(8, chrome - 12), (W - 8, chrome - 12)], fill=(48, 54, 61), width=1)
    for i, c in enumerate((DOT_R, DOT_Y, DOT_G)):
        x = 22 + i * 22
        d.ellipse([x, 16, x + 12, 28], fill=c)
    d.text((70, 14), title, font=font(15), fill=GRAY)
    y = chrome
    for ln in lines:
        col = color_for(ln)
        d.text((pad, y), ln, font=fnt, fill=col)
        y += lh
    img.save(out_path)
    print("saved", out_path, img.size)


def render_banner(out_path):
    W, H = 1200, 320
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, W - 1, H - 1], radius=18, outline=(88, 166, 255), width=3)
    d.text((60, 55), "BDB-GUARDIAN", font=font(72), fill=(88, 166, 255))
    d.text((62, 150), "Defensive monitor vs the BigDiskBuster technique", font=font(28), fill=FG)
    d.text((62, 195), "Defender-update DoS via disk exhaustion  |  MRT lock + volume handle + buster-file",
           font=font(22), fill=GRAY)
    pills = ["CLEAN", "CRITICAL", "CLEAN"]
    x = 62
    for p in pills:
        c = GREEN if p == "CLEAN" else RED
        d.rounded_rectangle([x, 248, x + 150, 288], radius=10, outline=c, width=2)
        bb = d.textbbox((0, 0), p, font=font(20))
        d.text((x + (150 - (bb[2] - bb[0])) // 2, 256), p, font=font(20), fill=c)
        x += 170
    d.text((x + 10, 256), "PowerShell  |  Windows  |  MIT", font=font(20), fill=GRAY)
    img.save(out_path)
    print("saved", out_path, img.size)


def read_lines(name):
    with open(os.path.join(CAP, name), encoding="utf-8", errors="replace") as fh:
        return [ln.rstrip("\n") for ln in fh]


def main():
    os.makedirs(DOCS, exist_ok=True)
    render_banner(os.path.join(DOCS, "banner.png"))
    det = read_lines("capture-02-detection.log")
    # Essential slice: findings + buster-file + verdict.
    crit = det[18:24] + [""] + det[31:37]
    render_terminal(crit, "BDB-Guardian - live detection (real output)",
                    os.path.join(DOCS, "capture-critical.png"))
    base = read_lines("capture-01-baseline.log")
    clean = base[11:17] + [""] + base[-5:-1]
    render_terminal(clean, "BDB-Guardian - baseline (real output)",
                    os.path.join(DOCS, "capture-baseline.png"))


if __name__ == "__main__":
    main()
