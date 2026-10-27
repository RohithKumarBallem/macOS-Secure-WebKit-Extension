#!/usr/bin/env python3
"""Renders the Secure WebKit shield icon at several sizes. Pure stdlib (zlib/struct).

    python3 Tools/make_icons.py

Writes Extension/Resources/images/icon-<size>.png and the app icon set.
"""
import os
import struct
import sys
import zlib

SS = 4  # supersampling factor per axis

SHIELD = [  # unit square, y down
    (0.50, 0.08), (0.84, 0.20), (0.84, 0.50), (0.78, 0.68),
    (0.64, 0.82), (0.50, 0.92), (0.36, 0.82), (0.22, 0.68),
    (0.16, 0.50), (0.16, 0.20),
]
CHECK = [(0.33, 0.50), (0.45, 0.63), (0.69, 0.35)]
CHECK_HALF_WIDTH = 0.045


def in_polygon(x, y, poly):
    inside = False
    j = len(poly) - 1
    for i in range(len(poly)):
        xi, yi = poly[i]
        xj, yj = poly[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def near_segment(x, y, a, b, half_width):
    ax, ay = a
    bx, by = b
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)))
    px, py = ax + t * dx, ay + t * dy
    return (x - px) ** 2 + (y - py) ** 2 <= half_width ** 2


def pixel(size, px, py, background):
    covered_shield = covered_check = 0
    for sy in range(SS):
        for sx in range(SS):
            x = (px + (sx + 0.5) / SS) / size
            y = (py + (sy + 0.5) / SS) / size
            if in_polygon(x, y, SHIELD):
                covered_shield += 1
                if any(near_segment(x, y, CHECK[i], CHECK[i + 1], CHECK_HALF_WIDTH) for i in range(len(CHECK) - 1)):
                    covered_check += 1
    n = SS * SS
    shield = covered_shield / n
    check = covered_check / n
    # vertical teal gradient on the shield, white check on top
    t = py / size
    base = (int(18 + 20 * t), int(150 - 40 * t), int(135 - 25 * t))
    r = base[0] * (1 - check) + 255 * check
    g = base[1] * (1 - check) + 255 * check
    b = base[2] * (1 - check) + 255 * check
    if background:
        # opaque rounded-square backdrop for the app icon
        cx = cy = size / 2
        half = size * 0.5
        radius = size * 0.22
        qx = max(abs(px + 0.5 - cx) - (half - radius), 0)
        qy = max(abs(py + 0.5 - cy) - (half - radius), 0)
        in_tile = qx * qx + qy * qy <= radius * radius
        if not in_tile:
            return (0, 0, 0, 0)
        bg = (236, 244, 243)
        return (int(bg[0] * (1 - shield) + r * shield),
                int(bg[1] * (1 - shield) + g * shield),
                int(bg[2] * (1 - shield) + b * shield), 255)
    return (int(r), int(g), int(b), int(round(255 * shield)))


def write_png(path, size, background):
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            row.extend(pixel(size, x, y, background))
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag, data):
        body = tag + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body) & 0xFFFFFFFF)

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(raw, 9))
    png += chunk(b"IEND", b"")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(png)


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ext = os.path.join(root, "Extension", "Resources", "images")
    for size in (48, 96, 128, 256, 512):
        write_png(os.path.join(ext, f"icon-{size}.png"), size, background=False)
    app = os.path.join(root, "App", "Assets.xcassets", "AppIcon.appiconset")
    for size in (16, 32, 64, 128, 256, 512, 1024):
        write_png(os.path.join(app, f"app-{size}.png"), size, background=True)
    print("icons written")


if __name__ == "__main__":
    sys.exit(main())
