#!/usr/bin/env python3
"""Draw the plugin icon (.claude-plugin/icon.png): a white shield with a check mark on a blue rounded square.

Standard library only (zlib + struct), deterministic, 512 x 512 with 4x4 supersampling.

    python scripts/make_icon.py
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

SIZE = 512
SS = 4  # supersampling per axis
BLUE = (47, 111, 222)
WHITE = (255, 255, 255)
ROOT = Path(__file__).resolve().parent.parent


def shield() -> list[tuple[float, float]]:
    """Outline in unit coordinates: flat shoulders, straight sides, a curved point at the bottom."""
    pts = [(0.50, 0.17), (0.76, 0.26), (0.76, 0.50)]
    for i in range(1, 17):  # quadratic curve from the right side down to the point
        t = i / 16
        x = (1 - t) ** 2 * 0.76 + 2 * (1 - t) * t * 0.74 + t * t * 0.50
        y = (1 - t) ** 2 * 0.50 + 2 * (1 - t) * t * 0.72 + t * t * 0.84
        pts.append((x, y))
    mirrored = [(1 - x, y) for x, y in reversed(pts[2:-1])]
    return pts + mirrored + [(0.24, 0.50), (0.24, 0.26)]


def check() -> list[tuple[float, float]]:
    return [(0.36, 0.50), (0.43, 0.43), (0.48, 0.49), (0.60, 0.35), (0.67, 0.42), (0.48, 0.62)]


def rounded_square(radius: float = 0.18) -> list[tuple[float, float]]:
    pts = []
    corners = ((1 - radius, radius, -90), (1 - radius, 1 - radius, 0), (radius, 1 - radius, 90), (radius, radius, 180))
    import math

    for cx, cy, start in corners:
        for i in range(13):
            a = math.radians(start + i * 7.5)
            pts.append((cx + radius * math.cos(a), cy + radius * math.sin(a)))
    return pts


def coverage(poly: list[tuple[float, float]]) -> list[list[float]]:
    """Fraction of each pixel inside the polygon (even-odd rule), by scanline over supersampled rows."""
    n = SIZE * SS
    cov = [[0.0] * SIZE for _ in range(SIZE)]
    edges = list(zip(poly, poly[1:] + poly[:1], strict=True))
    for row in range(n):
        y = (row + 0.5) / n
        xs = []
        for (x1, y1), (x2, y2) in edges:
            if (y1 <= y < y2) or (y2 <= y < y1):
                xs.append(x1 + (y - y1) * (x2 - x1) / (y2 - y1))
        xs.sort()
        out = cov[row // SS]
        for a, b in zip(xs[0::2], xs[1::2], strict=False):
            start, end = a * n, b * n
            for sub in range(max(0, int(start)), min(n, int(end) + 1)):
                left, right = max(start, sub), min(end, sub + 1)
                if right > left:
                    out[sub // SS] += (right - left) / (SS * SS)
    return cov


def main() -> int:
    background = coverage(rounded_square())
    body = coverage(shield())
    mark = coverage(check())
    rows = []
    for y in range(SIZE):
        line = bytearray([0])  # filter type 0
        for x in range(SIZE):
            alpha = min(1.0, background[y][x])
            white = min(1.0, body[y][x]) * (1 - min(1.0, mark[y][x]))
            rgb = [round(b * (1 - white) + w * white) for b, w in zip(BLUE, WHITE, strict=True)]
            line += bytes(rgb + [round(255 * alpha)])
        rows.append(bytes(line))

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", SIZE, SIZE, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b""))
    out = ROOT / ".claude-plugin" / "icon.png"
    out.write_bytes(png)
    print(f"wrote {out} ({len(png):,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
