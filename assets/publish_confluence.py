#!/usr/bin/env python3
"""
publish_confluence.py - publish the distroless base-image findings to Confluence.

Self-sufficient: everything it needs (report data, SVG diagrams, page markup)
lives in this file. The only other file it reads is settings.py sitting beside
it. Copy both files to the target system and run:

    python3 publish_confluence.py                  # publish
    python3 publish_confluence.py --dry-run        # write page.html, touch nothing
    python3 publish_confluence.py --export out/    # page.html + every SVG separately
    python3 publish_confluence.py --test           # verify credentials only

Diagrams are inline SVG, light theme, animated with SMIL. Every animation is
purely additive: each diagram renders complete and correct as a static image if
the renderer strips SMIL, which Confluence's sanitizer may do.

Timestamps are rendered in IST (Asia/Kolkata). The page stores no secrets and
the script never prints credentials.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.sax.saxutils
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

IST = ZoneInfo("Asia/Kolkata")

# =============================================================================
# THEME  - light only, per ~/.claude/ui.md
# =============================================================================
BG = "#F9FAFB"          # page background
CARD = "#FFFFFF"        # card surface
INK = "#111827"         # primary text
MUTED = "#4B5563"       # secondary text - never lighter
BORDER = "#E5E7EB"      # card border
OK = "#16A34A"          # success / zero findings
WARN = "#D97706"        # warning / fixable findings
BAD = "#DC2626"         # error / unfixable findings
ACCENT = "#2563EB"      # primary accent
ACCENT_SOFT = "#EFF6FF"  # accent tint (very light, never a dark fill)
OK_SOFT = "#F0FDF4"
WARN_SOFT = "#FFFBEB"
BAD_SOFT = "#FEF2F2"

FONT = "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"

# svg label rules: min size 12 for meaning, min colour MUTED, weight 600/400
L_SIZE, S_SIZE = 14, 12
L_W, S_W = 600, 400


def esc(value) -> str:
    """XML-escape for storage format and SVG text."""
    return xml.sax.saxutils.escape(str(value))


# =============================================================================
# REPORT DATA  - edit these blocks to change what gets published
# =============================================================================
REPORT = {
    "title": "Distroless Base Image Findings",
    "scanner": "Trivy 0.70.0",
    "method": "Published digest re-pulled from the registry, then re-scanned",
    "registry": "quay.io/hellodk",
    "scanned_at": datetime(2026, 10, 4, 19, 30, tzinfo=IST),
    "page_author": "hellodk",
}

# --- 1. Java runtime comparison: application images still carrying a JAR ------
JAVA_COMPARISON = [
    # label,                              os,  app,  size MB, digest8,   verdict
    ("UBI 9 Full cvefix2",                575,  0, 337.7, "fdc4f9ed", "unfixable"),
    ("Google Distroless fixed",            67,  0, 123.7, "ba8b0af3", "unfixable"),
    ("UBI 9 Micro fixed",                  56,  0, 147.3, "69ee63e7", "unfixable"),
    ("Temurin Alpine cvefix3",              0,  0, 135.9, "b924ecd3", "clean"),
    ("Corretto Alpine cvefix2",             0,  0, 220.5, "0185d185", "clean"),
    ("Hummingbird cvefix2",                 0,  0, 145.5, "5e123f11", "clean"),
]

# --- 2. Runtime-only Java bases: no application at all -----------------------
JAVA_BASE_ONLY = [
    ("hummingbird-4.0.2-java21-base", 102.7, 33, "67d22d2c"),
    ("temurin-4.0.2-java21-base",     178.2,  8, "24d9ae63"),
    ("corretto-4.0.2-java21-base",    158.4,  4, "a87313c9"),
]

# --- 3. Language runtime bases ----------------------------------------------
LANGUAGE_BASES = [
    # tag,                    ecosystem, version,     size MB, digest8,  findings
    ("node-22-base",          "Node.js",   "22.23.3",  57.9, "522a9703", 0),
    ("python-3.14-base",      "Python",    "3.14.8",   19.4, "8e5a940e", 0),
    ("golang-1.26-base",      "Go",        "1.26.8",   68.1, "a7517af4", 0),
    ("rust-1.99-base",        "Rust",      "1.99.0",  335.7, "d02e824a", 0),
]

# --- 4. Ninja troubleshooting image -----------------------------------------
NINJA = {
    "tag": "quay.io/hellodk/ninja:latest",
    "digest": "1fbe37db9a8af75f58c92968afd6912f716a1a0fb07723a91f9680dd87ad57a2",
    "base": "alpine:3.24",
    "compressed_mb": 167.0,
    "uncompressed_mb": 510.0,
    "layers": 13,
    "os_findings": 0,
    "app_findings": 0,
    "families": [
        ("Network", "curl wget ping ip ss dig nc socat nmap ngrep mtr "
                    "traceroute fping iperf3 tcpdump tshark whois ethtool"),
        ("Process", "ps top htop iotop strace lsof pidstat iostat sar "
                    "dmesg nsenter"),
        ("Shell", "bash vim nano find grep sed awk jq tree ncdu file stat "
                  "binutils"),
        ("MySQL / MariaDB", "mariadb 15.2 (mysql alias present)"),
        ("PostgreSQL", "psql 18.6, pg_dump, pg_restore"),
        ("Redis / Valkey", "redis-cli 8.8.0, valkey-cli 9.0.4"),
        ("SQLite / MongoDB", "sqlite3 3.53.4, mongostat, mongodump 100.14.1"),
        ("Aerospike", "libaerospike.so 7.6.2 built from source, asdb wrapper"),
        ("Elasticsearch", "py3-elasticsearch 7.11.0, es REST wrapper"),
        ("YugabyteDB", "yb wrapper over psql for YSQL, mongostat for DocDB"),
    ],
    "gaps": [
        ("Aerospike CLI", "No Alpine package. Upstream ascli is Java-only; "
                          "only the C client library ships."),
        ("Elasticsearch CLI", "No official CLI exists; es speaks the REST API "
                              "with curl and jq."),
        ("YugabyteDB shell", "ysqlsh is not packaged for Alpine; psql is the "
                             "upstream-supported YSQL client."),
        ("mongosh", "Alpine mongodb-tools ships mongostat/mongodump only."),
    ],
}

# --- 5. Application-layer CVEs no base image could remove --------------------
APP_LAYER_FIXES = [
    ("CRITICAL", 3, "org.apache.tomcat.embed:tomcat-embed-core", "11.0.24",
     "tomcat.version -> 11.0.25"),
    ("HIGH", 3, "com.fasterxml.jackson.core:jackson-databind", "managed",
     "jackson-bom -> 2.21.7"),
    ("HIGH", 2, "com.fasterxml.jackson.core:jackson-core", "managed",
     "jackson-bom -> 2.21.7"),
    ("HIGH", 3, "tools.jackson.core:jackson-databind", "managed",
     "jackson-bom.version -> 3.1.7"),
    ("HIGH", 2, "tools.jackson.core:jackson-core", "managed",
     "jackson-bom.version -> 3.1.7"),
    ("MEDIUM", 1, "org.springframework.retry:spring-retry", "1.0.3",
     "pin spring-retry -> 2.0.13 (CVE-2026-41710)"),
]

# --- 6. What was pushed ------------------------------------------------------
PUBLISHED = [
    # tag,                                    os, app, size MB, digest8
    ("hummingbird-4.0.2-java21-base",         0, "n/a", 102.7, "67d22d2c"),
    ("temurin-4.0.2-java21-base",             0, "n/a", 178.2, "24d9ae63"),
    ("corretto-4.0.2-java21-base",            0, "n/a", 158.4, "a87313c9"),
    ("node-22-base",                          0,    0,  57.9, "522a9703"),
    ("python-3.14-base",                      0,    0,  19.4, "8e5a940e"),
    ("golang-1.26-base",                      0,    0,  68.1, "a7517af4"),
    ("rust-1.99-base",                        0,    0, 335.7, "d02e824a"),
    ("ninja:latest",                          0,    0, 167.0, "1fbe37db"),
]


# =============================================================================
# SVG PRIMITIVES
# =============================================================================
def _defs(uid: str, tint: str = ACCENT) -> str:
    """Arrowhead markers. Unique per diagram so ids never collide on a page."""
    return (
        f'<defs>'
        f'<marker id="{uid}-ah" markerWidth="9" markerHeight="9" refX="7" '
        f'refY="4.5" orient="auto" markerUnits="strokeWidth">'
        f'<path d="M0,0 L8,4.5 L0,9 z" fill="{tint}"/></marker>'
        f'<marker id="{uid}-ahg" markerWidth="9" markerHeight="9" refX="7" '
        f'refY="4.5" orient="auto" markerUnits="strokeWidth">'
        f'<path d="M0,0 L8,4.5 L0,9 z" fill="{OK}"/></marker>'
        f'</defs>'
    )


def text(x, y, s, size=L_SIZE, weight=L_W, fill=INK, anchor="start",
         tracking=0) -> str:
    """SVG text. Every meaningful label is >=12px and >= #4B5563."""
    ls = f' letter-spacing="{tracking}"' if tracking else ""
    return (f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" '
            f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}"'
            f'{ls}>{esc(s)}</text>')


def card(x, y, w, h, title, sub=None, tint=CARD, edge=BORDER, accent=None,
         title_size=L_SIZE + 2, sub_size=S_SIZE) -> str:
    """Rounded component card: white surface, thin border, optional accent edge."""
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" '
           f'fill="{tint}" stroke="{edge}" stroke-width="1.5"/>']
    if accent:
        out.append(f'<rect x="{x}" y="{y}" width="4" height="{h}" rx="2" '
                   f'fill="{accent}"/>')
    inner = x + 16
    if sub:
        cy = y + h / 2
        out.append(text(inner, cy - 5, title, title_size, L_W, INK))
        out.append(text(inner, cy + 16, sub, sub_size, S_W, MUTED))
    else:
        out.append(text(inner, y + h / 2 + 5, title, title_size, L_W, INK))
    return "".join(out)


def badge(x, y, label, fill=OK, w=None) -> str:
    """Pill badge with readable text (fill is always a light tint)."""
    w = w or (len(label) * 7 + 22)
    dark = fill
    txt = {"#16A34A": OK, "#D97706": WARN, "#DC2626": BAD}.get(fill, fill)
    return (f'<rect x="{x}" y="{y}" width="{w}" height="24" rx="12" '
            f'fill="{dark}" opacity="0.14"/>'
            f'{text(x + w / 2, y + 16, label, S_SIZE, L_W, txt, "middle")}')


def radar_ping(cx, cy, colour=OK, r0=8, r1=30, dur="2.4s", uid="p") -> str:
    """Expanding/fading ring. Static state is a visible ring, not blank."""
    return (
        f'<circle cx="{cx}" cy="{cy}" r="{r0}" fill="none" stroke="{colour}" '
        f'stroke-width="2" opacity="0.85">'
        f'<animate attributeName="r" values="{r0};{r1}" dur="{dur}" '
        f'repeatCount="indefinite"/>'
        f'<animate attributeName="opacity" values="0.85;0" dur="{dur}" '
        f'repeatCount="indefinite"/>'
        f'</circle>'
        f'<circle cx="{cx}" cy="{cy}" r="3.5" fill="{colour}"/>'
    )


def flow_dot(path_abs, start, colour=ACCENT, dur="2.6s", delay="0s") -> str:
    """
    Travelling dot whose motion path exactly overlays the drawn line.

    The dot is placed at the absolute start point, and animateMotion carries a
    path relative to that point. If SMIL is stripped the dot simply sits at the
    start of the line instead of appearing at the SVG origin.
    """
    sx, sy = start
    # convert the absolute path to a relative one so cx/cy can hold the start
    rel = _relative_path(path_abs, sx, sy)
    return (
        f'<circle cx="{sx}" cy="{sy}" r="4.5" fill="{colour}" '
        f'stroke="{CARD}" stroke-width="1.5">'
        f'<animateMotion dur="{dur}" begin="{delay}" repeatCount="indefinite" '
        f'path="{rel}"/>'
        f'</circle>'
    )


def _relative_path(d: str, sx: float, sy: float) -> str:
    """Rewrite an absolute M/H/V/L path as relative to (sx, sy)."""
    toks = d.replace(",", " ").split()
    out, i, cx, cy, px, py = [], 0, float(sx), float(sy), float(sx), float(sy)
    while i < len(toks):
        c = toks[i]
        if c in "Mm":
            i += 1
            nx, ny = float(toks[i]), float(toks[i + 1])
            out.append(f"M{nx - sx:g},{ny - sy:g}")
            cx, cy = nx, ny
            i += 2
        elif c in "Hh":
            i += 1
            nx = float(toks[i])
            out.append(f"H{nx - cx:g}")
            cx = nx
            i += 1
        elif c in "Vv":
            i += 1
            ny = float(toks[i])
            out.append(f"V{ny - cy:g}")
            cy = ny
            i += 1
        elif c in "Ll":
            i += 1
            nx, ny = float(toks[i]), float(toks[i + 1])
            out.append(f"L{nx - cx:g},{ny - cy:g}")
            cx, cy = nx, ny
            i += 2
        else:
            i += 1
    return " ".join(out)


def svg_open(w, h, uid, title) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" '
        f'width="100%" style="max-width:{w}px;height:auto;display:block;'
        f'margin:16px 0" role="img" aria-label="{esc(title)}" '
        f'font-family="{FONT}">'
        f'<title>{esc(title)}</title>' + _defs(uid)
    )


# =============================================================================
# DIAGRAM 1 - remediation pipeline (4 stages, left to right)
# =============================================================================
def diagram_pipeline() -> str:
    uid = "pipe"
    W, H = 1188, 300
    stages = [
        ("Application Layer", "13 High / Critical + 1 Medium", BAD, BAD_SOFT),
        ("Base Image", "67 / 56 / 575 OS findings", WARN, WARN_SOFT),
        ("Remediation", "Pin, patch, rebuild, verify", ACCENT, ACCENT_SOFT),
        ("Verified Clean", "0 OS / 0 application", OK, OK_SOFT),
    ]
    y, ch, cw = 96, 148, 228
    parts = [svg_open(W, H, uid, "Remediation pipeline from layered findings to a verified clean image"),
             text(24, 46, "How The Findings Were Cleared", 24, 700, INK),
             text(24, 70, "Four Stages From Application Layers To A Verified Registry Digest",
                  L_SIZE, S_W, MUTED, tracking=0.6),
             f'<rect x="24" y="84" width="{W - 48}" height="{H - 108}" rx="16" '
             f'fill="{CARD}" stroke="{BORDER}" stroke-width="1.5"/>']
    xs = []
    for i, (t, s, tint, soft) in enumerate(stages):
        x = 56 + i * 292
        xs.append(x)
        parts.append(card(x, y, cw, ch, t, s, tint=soft, accent=tint))
        parts.append(badge(x + 16, y + ch - 40,
                           f"Stage {i + 1}", tint))
        if i == 3:
            cx, cy = x + cw - 34, y + 34
            parts.append(radar_ping(cx, cy, OK, uid=uid))
    # straight horizontal arrows only
    for i in range(3):
        x0, x1 = xs[i] + cw + 8, xs[i + 1] - 8
        cy = y + ch / 2
        parts.append(f'<line x1="{x0}" y1="{cy}" x2="{x1}" y2="{cy}" '
                     f'stroke="{ACCENT}" stroke-width="2" '
                     f'marker-end="url(#{uid}-ah)"/>')
        parts.append(flow_dot(f"M {x0} {cy} H {x1}", (x0, cy),
                              ACCENT, dur="2.2s", delay=f"{i * 0.45:g}s"))
        parts.append(text((x0 + x1) / 2, cy - 14,
                          ["Fixed", "Patched", "Re-Pulled"][i],
                          S_SIZE, L_W, MUTED, "middle"))
    parts.append("</svg>")
    return "".join(parts)


# =============================================================================
# DIAGRAM 2 - registry fan-out (straight arrows via a shared bus)
# =============================================================================
def diagram_registry() -> str:
    uid = "reg"
    W, H = 940, 700
    rows = [
        ("Java 21", "Hummingbird / Temurin / Corretto", OK, 0),
        ("Node.js 22", "npm removed - runtime only", OK, 0),
        ("Python 3.14", "pip removed - runtime only", OK, 0),
        ("Go 1.26", "builder image", OK, 0),
        ("Rust 1.99", "builder image", OK, 0),
        ("Ninja", "167 MB troubleshooting image", ACCENT, 0),
    ]
    parts = [svg_open(W, H, uid, "Published base image families fanning out from a single registry"),
             text(24, 46, "Published Base Image Families", 24, 700, INK),
             text(24, 70, "One Repository, Eight Images, Zero Findings On Every One",
                  L_SIZE, S_W, MUTED, tracking=0.6),
             f'<rect x="24" y="84" width="{W - 48}" height="{H - 108}" rx="16" '
             f'fill="{BG}" stroke="{BORDER}" stroke-width="1.5"/>']

    # central anchor - light surface with a strong accent edge (no dark fills)
    row_x, row_w, row_h, gap = 566, 320, 64, 20
    top = 120
    centers = [top + i * (row_h + gap) + row_h / 2 for i in range(len(rows))]
    bus_x = 486
    cx0, cw0, ch0 = 56, 300, 168
    trunk_y = (centers[0] + centers[-1]) / 2
    cy0 = trunk_y - ch0 / 2

    parts.append(f'<rect x="{cx0}" y="{cy0:.0f}" width="{cw0}" height="{ch0}" rx="14" '
                 f'fill="{ACCENT_SOFT}" stroke="{ACCENT}" stroke-width="2.5"/>')
    parts.append(text(cx0 + 24, cy0 + 46, "Base Image Registry", 20, 700, INK))
    parts.append(text(cx0 + 24, cy0 + 74, "quay.io/hellodk", 14, L_W, ACCENT))
    parts.append(text(cx0 + 24, cy0 + 104, "base-image  +  ninja", 13, S_W, MUTED))
    parts.append(text(cx0 + 24, cy0 + 132, "Digest verified after push",
                      13, S_W, MUTED))
    parts.append(radar_ping(cx0 + cw0 - 34, cy0 + 34, ACCENT, uid=uid))

    # geometry: trunk -> vertical bus -> horizontal branch per row (no diagonals)
    parts.append(f'<line x1="{cx0 + cw0}" y1="{trunk_y}" x2="{bus_x}" '
                 f'y2="{trunk_y}" stroke="{ACCENT}" stroke-width="2.5"/>')
    parts.append(f'<line x1="{bus_x}" y1="{centers[0]}" x2="{bus_x}" '
                 f'y2="{centers[-1]}" stroke="{ACCENT}" stroke-width="2.5"/>')

    for i, (t, s, tint, _) in enumerate(rows):
        ry = top + i * (row_h + gap)
        cy = centers[i]
        parts.append(f'<line x1="{bus_x}" y1="{cy}" x2="{row_x}" y2="{cy}" '
                     f'stroke="{ACCENT}" stroke-width="2" '
                     f'marker-end="url(#{uid}-ah)"/>')
        parts.append(card(row_x, ry, row_w, row_h, t, s, tint=CARD,
                          accent=tint, title_size=16))
        # dot travels trunk -> bus -> branch, matching the visible segments
        parts.append(flow_dot(
            f"M {cx0 + cw0} {trunk_y} H {bus_x} V {cy} H {row_x}",
            (cx0 + cw0, trunk_y), ACCENT, dur="3.4s",
            delay=f"{i * 0.3:g}s"))

    # legend
    ly = top + (len(rows) - 1) * (row_h + gap) + row_h + 42
    for j, (col, lab) in enumerate([(OK, "Zero Findings"), (ACCENT, "Troubleshooting")]):
        lx = 330 + j * 220
        parts.append(f'<circle cx="{lx}" cy="{ly}" r="6" fill="{col}"/>')
        parts.append(text(lx + 14, ly + 5, lab, S_SIZE, S_W, MUTED))
    parts.append("</svg>")
    return "".join(parts)


# =============================================================================
# DIAGRAM 3 - findings comparison (animated bars)
# =============================================================================
def diagram_bars() -> str:
    uid = "bar"
    W, H = 980, 540
    base_y, top_y = 396, 130
    plot_h = base_y - top_y
    x0, bw, step = 100, 96, 148
    mx = max(v for _, v, *_ in JAVA_COMPARISON)
    # two-line x-axis labels so nothing crosses the panel edge
    short = [("UBI 9 Full", "cvefix2"), ("Google", "Distroless fixed"),
             ("UBI Micro", "fixed"), ("Temurin", "Alpine cvefix3"),
             ("Corretto", "Alpine cvefix2"), ("Hummingbird", "cvefix2")]

    parts = [svg_open(W, H, uid, "Application image finding counts by runtime"),
             text(24, 46, "Findings Per Application Image", 24, 700, INK),
             text(24, 70, "OS Layer Findings After Remediation - Trivy 0.70.0",
                  L_SIZE, S_W, MUTED, tracking=0.6),
             f'<rect x="24" y="84" width="{W - 48}" height="{H - 108}" rx="16" '
             f'fill="{CARD}" stroke="{BORDER}" stroke-width="1.5"/>']

    # gridlines
    for gv in (0, 100, 200, 300, 400, 500):
        gy = base_y - (gv / mx) * plot_h
        parts.append(f'<line x1="88" y1="{gy:.1f}" x2="940" y2="{gy:.1f}" '
                     f'stroke="{BORDER}" stroke-width="1"/>')
        parts.append(text(78, gy + 4, str(gv), S_SIZE, S_W, MUTED, "end"))
    parts.append(f'<line x1="88" y1="{base_y}" x2="940" y2="{base_y}" '
                 f'stroke="{MUTED}" stroke-width="1.5"/>')
    parts.append(text(940, 112, "Zero = no findings   |   Blocked = upstream has published no fix",
                      S_SIZE, S_W, MUTED, "end"))

    for i, (_label, osv, _app, size, _d, verdict) in enumerate(JAVA_COMPARISON):
        name, detail = short[i]
        bx = x0 + i * step
        cx = bx + bw / 2
        h = (osv / mx) * plot_h
        colour = OK if osv == 0 else (WARN if osv < 100 else BAD)
        if osv == 0:
            # zero findings: green marker at the baseline plus an explicit "0"
            parts.append(f'<rect x="{bx}" y="{base_y - 6}" width="{bw}" '
                         f'height="6" rx="3" fill="{OK}" opacity="0.35"/>')
            parts.append(f'<circle cx="{cx}" cy="{base_y - 40}" '
                         f'r="26" fill="{OK_SOFT}" stroke="{OK}" '
                         f'stroke-width="2"/>')
            parts.append(text(cx, base_y - 33, "0", 22, 700, OK, "middle"))
        else:
            by = base_y - h
            parts.append(f'<rect x="{bx}" y="{by:.1f}" width="{bw}" '
                         f'height="{h:.1f}" rx="6" fill="{colour}" '
                         f'opacity="0.9">'
                         f'<animate attributeName="y" from="{base_y}" '
                         f'to="{by:.1f}" dur="1.1s" begin="0.2s" '
                         f'fill="freeze"/>'
                         f'<animate attributeName="height" from="0" '
                         f'to="{h:.1f}" dur="1.1s" begin="0.2s" '
                         f'fill="freeze"/></rect>')
            parts.append(text(cx, by - 12, str(osv), L_SIZE, 700,
                              colour, "middle"))
        parts.append(text(cx, base_y + 26, name, 13, L_W, INK, "middle"))
        parts.append(text(cx, base_y + 44, detail, S_SIZE, S_W, MUTED, "middle"))
        parts.append(text(cx, base_y + 64, f"{size} MB", S_SIZE, S_W,
                          MUTED, "middle"))
        pill = "Zero" if verdict == "clean" else "Blocked"
        tint = OK if verdict == "clean" else WARN
        pw = len(pill) * 7 + 22
        parts.append(badge(cx - pw / 2, base_y + 80, pill, tint))
    parts.append("</svg>")
    return "".join(parts)


# =============================================================================
# DIAGRAM 4 - application image vs runtime-only base
# =============================================================================
def diagram_anatomy() -> str:
    uid = "ana"
    W, H = 980, 440
    parts = [svg_open(W, H, uid, "Application image compared with a runtime-only base image"),
             text(24, 46, "Application Image Versus Runtime-Only Base", 24, 700, INK),
             text(24, 70, "Why The Application Column Reads N/A Rather Than Zero On The Base Tags",
                  L_SIZE, S_W, MUTED, tracking=0.6),
             f'<rect x="24" y="84" width="{W - 48}" height="{H - 108}" rx="16" '
             f'fill="{BG}" stroke="{BORDER}" stroke-width="1.5"/>']

    panels = [
        (40, "Application Image", "Carries the JAR", WARN, WARN_SOFT,
         [("Runtime", "JVM 21", CARD, MUTED),
          ("Base OS", "Alpine / Debian", CARD, MUTED),
          ("Application", "app.jar 68.8 MB", BAD_SOFT, BAD),
          ("Entrypoint", "java -jar app.jar", BAD_SOFT, BAD)]),
        (512, "Runtime-Only Base", "No application at all", OK, OK_SOFT,
         [("Runtime", "JVM 21", CARD, MUTED),
          ("Base OS", "Alpine / Debian", CARD, MUTED),
          ("Application", "not present", OK_SOFT, OK),
          ("Entrypoint", "none - you supply it", OK_SOFT, OK)]),
    ]
    for px, title, sub, tint, soft, layers in panels:
        parts.append(f'<rect x="{px}" y="112" width="428" height="264" rx="14" '
                     f'fill="{CARD}" stroke="{tint}" stroke-width="2"/>')
        parts.append(text(px + 24, 150, title, 20, 700, INK))
        parts.append(badge(px + 24, 164, sub, tint))
        for j, (lt, lv, bg, fg) in enumerate(layers):
            ly = 206 + j * 44
            parts.append(f'<rect x="{px + 24}" y="{ly}" width="380" '
                         f'height="36" rx="8" fill="{bg}" stroke="{BORDER}" '
                         f'stroke-width="1"/>')
            parts.append(text(px + 40, ly + 23, lt, 13, L_W, MUTED))
            parts.append(text(px + 160, ly + 23, lv, 13, L_W, fg))
        if tint == OK:
            parts.append(radar_ping(px + 396, 148, OK, uid=uid))
    parts.append(f'<line x1="492" y1="244" x2="480" y2="244" '
                 f'stroke="{MUTED}" stroke-width="2" '
                 f'marker-end="url(#{uid}-ah)"/>')
    parts.append(text(W / 2, 232, "Rebuilt", S_SIZE, L_W, MUTED, "middle"))
    parts.append("</svg>")
    return "".join(parts)


# =============================================================================
# PAGE MARKUP - Confluence storage format (XHTML)
# =============================================================================
def _stat_strip() -> str:
    cells = [
        ("Images Published", str(len(PUBLISHED)), ACCENT),
        ("Findings On Published Set", "0", OK),
        ("Application Layer Fixes", str(sum(r[1] for r in APP_LAYER_FIXES)), WARN),
        ("Diagram Count", "4", ACCENT),
    ]
    th = "".join(
        f'<th style="background:{ACCENT_SOFT};border:1px solid {BORDER};'
        f'padding:12px 14px;text-align:left;font-size:12px;color:{MUTED};'
        f'letter-spacing:0.6px;text-transform:uppercase">{esc(k)}</th>'
        for k, _, _ in cells)
    td = "".join(
        f'<td style="background:{CARD};border:1px solid {BORDER};padding:14px">'
        f'<div style="font-size:26px;font-weight:700;color:{c}">{esc(v)}</div>'
        f'<div style="font-size:12px;color:{MUTED}">{esc(k)}</div></td>'
        for k, v, c in cells)
    return (f'<table style="border-collapse:collapse;width:100%"><thead><tr>{th}'
            f'</tr></thead><tbody><tr>{td}</tr></tbody></table>')


def _table(headers, rows, colour_first=False) -> str:
    head = "".join(
        f'<th style="background:{ACCENT_SOFT};border:1px solid {BORDER};'
        f'padding:10px 12px;text-align:left;font-size:12px;color:{MUTED};'
        f'letter-spacing:0.6px;text-transform:uppercase">{esc(h)}</th>'
        for h in headers)
    body = []
    for i, r in enumerate(rows):
        shade = CARD if i % 2 == 0 else BG
        tds = []
        for j, cell in enumerate(r):
            colour = INK
            if colour_first and j == 0:
                s = str(cell).strip()
                colour = OK if s in ("0", "High", "Critical", "Critical", "Clean") \
                    else (BAD if s in ("575", "CRITICAL") else
                          (WARN if s in ("56", "67", "HIGH", "MEDIUM") else INK))
            tds.append(
                f'<td style="background:{shade};border:1px solid {BORDER};'
                f'padding:9px 12px;font-size:13px;color:{colour}">'
                f'{esc(cell)}</td>')
        body.append(f'<tr>{"".join(tds)}</tr>')
    return (f'<table style="border-collapse:collapse;width:100%">'
            f'<thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table>')


def _note(kind: str, title: str, body: str) -> str:
    """Confluence info/success/warning macro - available on Cloud and DC."""
    name = {"info": "info", "ok": "success", "warn": "warning"}.get(kind, "info")
    return (
        f'<ac:structured-macro ac:name="{name}">'
        f'<ac:parameter ac:name="title">{esc(title)}</ac:parameter>'
        f'<ac:rich-text-body><p>{body}</p></ac:rich-text-body>'
        f'</ac:structured-macro>'
    )


def _h(level: int, s: str) -> str:
    return f'<h{level}>{esc(s)}</h{level}>'


def _p(s: str, muted=False) -> str:
    style = f' style="color:{MUTED}"' if muted else ""
    return f'<p{style}>{s}</p>'


def build_page() -> str:
    """Assemble the full Confluence storage-format document."""
    ts = REPORT["scanned_at"].strftime("%d %b %Y, %H:%M:%S").strip() + " IST"
    parts = [
        _h(1, REPORT["title"]),
        _p(f'<strong>Generated</strong> {esc(ts)} &#160;|&#160; '
           f'<strong>Scanner</strong> {esc(REPORT["scanner"])} &#160;|&#160; '
           f'<strong>Registry</strong> {esc(REPORT["registry"])} &#160;|&#160; '
           f'<strong>Method</strong> {esc(REPORT["method"])}', muted=True),
        '<hr/>',
        _h(2, "Summary"),
        _stat_strip(),
        _p(""),
        diagram_pipeline(),
        _note("ok", "Zero findings on the published set",
              "All eight published images were re-pulled by digest from the "
              "registry and scanned again. The scanner reported 0 OS and 0 "
              "application findings on every one of them."),
        _h(2, "Application Image Comparison"),
        _p("Six Java runtime families, each still carrying the original "
           "application. Three reach zero. Three cannot, because the vendor has "
           "published no fix.", muted=True),
        diagram_bars(),
        _table(
            ["Runtime", "OS", "App", "Size", "Digest", "Verdict"],
            [(l, o, a, f"{s} MB", d, v.title())
             for l, o, a, s, d, v in JAVA_COMPARISON],
            colour_first=True),
        _note("warn", "Why three families cannot reach zero",
              "Red Hat has published no erratum for pcre2 or glibc, and Debian "
              "has not rebuilt glibc, libexpat1 or libuuid1. Those floors are "
              "vendor-blocked, not accepted risk."),
        _h(2, "Published Base Images"),
        _p("A base image carries the runtime and nothing else - no JAR, no "
           "application entrypoint.", muted=True),
        diagram_registry(),
        _table(
            ["Tag", "OS", "App", "Size", "Digest"],
            [(t, o, a, f"{s} MB", d) for t, o, a, s, d in PUBLISHED],
            colour_first=True),
        _h(3, "Runtime-Only Java Bases"),
        _table(
            ["Tag", "Size", "Layers", "Digest"],
            [(t, f"{s} MB", str(l), d) for t, s, l, d in JAVA_BASE_ONLY]),
        _h(3, "Language Bases"),
        _table(
            ["Ecosystem", "Tag", "Version", "Size", "Digest", "Findings"],
            [(e, t, v, f"{s} MB", d, str(f))
             for t, e, v, s, d, f in LANGUAGE_BASES]),
        _h(3, "Runtime-Only Versus Application Image"),
        diagram_anatomy(),
        _note("info", "The application column reads N/A on base tags",
              "A base image contains no application, so there is nothing to "
              "scan in that layer. The column reads N/A rather than 0 because "
              "0 would claim a clean application that does not exist."),
        _h(2, "Ninja Troubleshooting Image"),
        _p(f"<strong>{esc(NINJA['tag'])}</strong> &#160;|&#160; base "
           f"{esc(NINJA['base'])} &#160;|&#160; {NINJA['compressed_mb']} MB "
           f"compressed across {NINJA['layers']} layers &#160;|&#160; "
           f"{NINJA['os_findings']} OS / {NINJA['app_findings']} application "
           f"findings", muted=True),
        _table(
            ["Capability", "Contents"],
            [(k, v) for k, v in NINJA["families"]]),
        _h(3, "Known Gaps In The Ninja Image"),
        _table(["Component", "Why It Is Missing"], [(k, v) for k, v in NINJA["gaps"]]),
        _h(2, "Application Layer Fixes"),
        _p("Layer splitting exposed findings that no base image could remove. "
           "These were resolved in the application build itself.", muted=True),
        _table(
            ["Severity", "Count", "Library", "Installed", "Fix Applied"],
            [(s, str(n), lib, ins, fix)
             for s, n, lib, ins, fix in APP_LAYER_FIXES],
            colour_first=True),
        _note("info", "The Jackson case is the instructive one",
              "Spring Boot 4 runs the 2.x and 3.x Jackson trains in parallel "
              "and its parent manages only the newer one, so a routine version "
              "bump leaves the legacy train exactly where it was."),
        '<hr/>',
        _p(f"Generated by publish_confluence.py v{esc(REPORT_VERSION)} - "
           f"timestamps in IST (Asia/Kolkata).", muted=True),
    ]
    return "".join(parts)


REPORT_VERSION = "1.0.0"


# =============================================================================
# SETTINGS
# =============================================================================
def load_settings(path: Path) -> object:
    if not path.exists():
        sys.exit(
            f"settings.py not found at {path}\n"
            f"Create it beside this script. See the docstring at the top of "
            f"settings.py for a filled-in template."
        )
    spec = importlib.util.spec_from_file_location("settings", path)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Could not import {path}: {exc}")
    return mod


def describe_settings(s) -> str:
    """Connection summary that never contains a secret."""
    base = getattr(s, "CONFLUENCE_BASE_URL", "")
    auth = getattr(s, "AUTH_TYPE", "cloud")
    if auth == "cloud":
        who = getattr(s, "EMAIL", "")
    elif auth == "pat":
        who = "personal access token"
    else:
        who = getattr(s, "USERNAME", "")
    return (f"host={base}  space={getattr(s, 'SPACE_KEY', '')}  "
            f"auth={auth}  identity={who}")


def _auth_header(s) -> str:
    auth = getattr(s, "AUTH_TYPE", "cloud").lower()
    if auth == "cloud":
        email, token = getattr(s, "EMAIL", ""), getattr(s, "API_TOKEN", "")
        if not email or not token or token.startswith("REPLACE"):
            sys.exit("settings.py: EMAIL and API_TOKEN are required for AUTH_TYPE='cloud'.")
        raw = f"{email}:{token}".encode()
        return "Basic " + base64.b64encode(raw).decode()
    if auth == "pat":
        pat = getattr(s, "PAT", "")
        if not pat:
            sys.exit("settings.py: PAT is required for AUTH_TYPE='pat'.")
        return "Bearer " + pat
    if auth == "basic":
        u, p = getattr(s, "USERNAME", ""), getattr(s, "PASSWORD", "")
        if not u or not p:
            sys.exit("settings.py: USERNAME and PASSWORD are required for AUTH_TYPE='basic'.")
        raw = f"{u}:{p}".encode()
        return "Basic " + base64.b64encode(raw).decode()
    sys.exit(f"settings.py: unknown AUTH_TYPE {auth!r} (use 'cloud', 'pat' or 'basic').")


# =============================================================================
# CONFLUENCE CLIENT
# =============================================================================
class Confluence:
    def __init__(self, s):
        self.base = getattr(s, "CONFLUENCE_BASE_URL", "").rstrip("/")
        self.space = getattr(s, "SPACE_KEY", "")
        self.title = getattr(s, "PAGE_TITLE", "")
        self.parent = getattr(s, "PARENT_PAGE_ID", None)
        self.auth = _auth_header(s)
        if not self.base or self.base.startswith("https://YOUR-SITE"):
            sys.exit("settings.py: CONFLUENCE_BASE_URL is not set.")
        if not self.space:
            sys.exit("settings.py: SPACE_KEY is not set.")

    def _request(self, method, path, payload=None, params=None):
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", self.auth)
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                body = resp.read().decode()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode()[:400]
            # never echo the request headers - they carry credentials
            raise RuntimeError(f"{method} {path} -> HTTP {exc.code}: {detail}") from None
        except urllib.error.URLError as exc:
            raise RuntimeError(f"{method} {path} -> unreachable: {exc.reason}") from None

    def ping(self) -> dict:
        return self._request("GET", "/rest/api/content",
                             params={"limit": 1, "expand": "space"})

    def find(self) -> dict | None:
        res = self._request("GET", "/rest/api/content", params={
            "spaceKey": self.space, "title": self.title,
            "expand": "version", "limit": 1})
        results = res.get("results") or []
        return results[0] if results else None

    def create(self, storage: str) -> dict:
        payload = {
            "type": "page",
            "title": self.title,
            "space": {"key": self.space},
            "body": {"storage": {"value": storage, "representation": "storage"}},
        }
        if self.parent:
            payload["ancestors"] = [{"id": str(self.parent)}]
        return self._request("POST", "/rest/api/content", payload)

    def update(self, page: dict, storage: str) -> dict:
        payload = {
            "id": page["id"],
            "type": page.get("type", "page"),
            "title": self.title,
            "space": {"key": self.space},
            "version": {"number": page["version"]["number"] + 1,
                        "message": "publish_confluence.py"},
            "body": {"storage": {"value": storage, "representation": "storage"}},
        }
        return self._request("PUT", f"/rest/api/content/{page['id']}", payload)


# =============================================================================
# CLI
# =============================================================================
def _export(storage: str, outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "page.html").write_text(storage, encoding="utf-8")
    diagrams = {"01-pipeline": diagram_pipeline, "02-registry": diagram_registry,
                "03-findings": diagram_bars, "04-anatomy": diagram_anatomy}
    for name, fn in diagrams.items():
        (outdir / f"{name}.svg").write_text(fn(), encoding="utf-8")
    print(f"wrote {outdir}/page.html and {len(diagrams)} SVGs", file=sys.stderr)


# =============================================================================
# BROWSER PREVIEW - self-contained HTML that shows the page as Confluence will
# =============================================================================
PREVIEW_CSS = f"""
:root {{
  --bg:{BG}; --card:{CARD}; --ink:{INK}; --muted:{MUTED}; --border:{BORDER};
  --accent:{ACCENT}; --accent-soft:{ACCENT_SOFT};
  --ok:{OK}; --ok-soft:{OK_SOFT}; --warn:{WARN}; --warn-soft:{WARN_SOFT};
  --bad:{BAD}; --bad-soft:{BAD_SOFT};
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font-family:{FONT};
        font-size:14px; line-height:1.6; }}
.topbar {{ position:sticky; top:0; z-index:9; background:var(--card);
           border-bottom:1px solid var(--border); padding:12px 28px;
           display:flex; align-items:center; gap:14px; }}
.topbar .dot {{ width:10px; height:10px; border-radius:50%; background:var(--ok); }}
.topbar .name {{ font-weight:700; }}
.topbar .meta {{ color:var(--muted); font-size:12px; margin-left:auto; }}
.page {{ max-width:1100px; margin:28px auto 64px; background:var(--card);
         border:1px solid var(--border); border-radius:14px;
         padding:36px 44px 44px; }}
h1 {{ font-size:28px; line-height:1.25; margin:0 0 12px; letter-spacing:-0.3px; }}
h2 {{ font-size:20px; margin:38px 0 12px; padding-bottom:8px;
      border-bottom:1px solid var(--border); }}
h3 {{ font-size:16px; margin:26px 0 10px; color:var(--ink); }}
p {{ margin:10px 0; }}
hr {{ border:0; border-top:1px solid var(--border); margin:30px 0; }}
table {{ border-collapse:collapse; width:100%; margin:14px 0; font-size:13px; }}
th {{ background:var(--accent-soft); border:1px solid var(--border);
      padding:10px 12px; text-align:left; font-size:12px; color:var(--muted);
      letter-spacing:0.6px; text-transform:uppercase; font-weight:600; }}
td {{ border:1px solid var(--border); padding:9px 12px; background:var(--card); }}
tr:nth-child(even) td {{ background:var(--bg); }}
svg {{ max-width:100%; height:auto; display:block; margin:18px 0;
       background:var(--card); border:1px solid var(--border);
       border-radius:12px; padding:8px; }}
.callout {{ border:1px solid var(--border); border-left:4px solid var(--accent);
            border-radius:10px; padding:14px 18px; margin:18px 0;
            background:var(--accent-soft); }}
.callout .ctitle {{ font-weight:700; font-size:13px; margin-bottom:4px; }}
.callout p {{ margin:4px 0; }}
.callout.success {{ border-left-color:var(--ok); background:var(--ok-soft); }}
.callout.success .ctitle {{ color:var(--ok); }}
.callout.warning {{ border-left-color:var(--warn); background:var(--warn-soft); }}
.callout.warning .ctitle {{ color:var(--warn); }}
.callout.info .ctitle {{ color:var(--accent); }}
.note {{ color:var(--muted); font-size:12.5px; }}
@media (max-width:760px) {{ .page {{ padding:22px 16px; }} }}
"""

PREVIEW_JS = r"""
document.querySelectorAll('ac\\:structured-macro').forEach(function (m) {
  var kind = (m.getAttribute('ac:name') || 'info').toLowerCase();
  if (kind === 'success') kind = 'success';
  else if (kind === 'warning') kind = 'warning';
  else kind = 'info';
  var p = m.querySelector('ac\\:parameter');
  var title = p ? p.textContent.trim() : '';
  var body = m.querySelector('ac\\:rich-text-body');
  var div = document.createElement('div');
  div.className = 'callout ' + kind;
  div.innerHTML = '<div class="ctitle"></div>';
  div.firstChild.textContent = title;
  if (body) { var c = body.cloneNode(true); while (c.firstChild) div.appendChild(c.firstChild); }
  m.replaceWith(div);
});
"""


def build_preview(storage: str) -> str:
    ts = REPORT["scanned_at"].strftime("%d %b %Y, %H:%M:%S") + " IST"
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{esc(REPORT['title'])} - preview</title>"
        f"<style>{PREVIEW_CSS}</style></head><body>"
        f"<div class=\"topbar\"><span class=\"dot\"></span>"
        f"<span class=\"name\">{esc(REPORT['title'])}</span>"
        f"<span>preview only - not yet published</span>"
        f"<span class=\"meta\">{esc(ts)} &#183; {esc(REPORT['scanner'])}</span></div>"
        f"<main class=\"page\">{storage}</main>"
        f"<script>{PREVIEW_JS}</script></body></html>"
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Publish base-image findings to Confluence.")
    ap.add_argument("--settings", default=str(Path(__file__).with_name("settings.py")),
                    help="path to settings.py")
    ap.add_argument("--dry-run", action="store_true",
                    help="build page.html only, do not contact Confluence")
    ap.add_argument("--export", metavar="DIR",
                    help="write page.html and each SVG into DIR")
    ap.add_argument("--preview", nargs="?", const="preview.html", metavar="FILE",
                    help="write a self-contained browser preview (default preview.html)")
    ap.add_argument("--test", action="store_true",
                    help="verify credentials and exit")
    ap.add_argument("--space", help="override SPACE_KEY")
    ap.add_argument("--title", help="override PAGE_TITLE")
    ap.add_argument("--parent", help="override PARENT_PAGE_ID")
    args = ap.parse_args(argv)

    s = load_settings(Path(args.settings).resolve())
    if args.space:
        setattr(s, "SPACE_KEY", args.space)
    if args.title:
        setattr(s, "PAGE_TITLE", args.title)
    if args.parent:
        setattr(s, "PARENT_PAGE_ID", args.parent)
    global REPORT_VERSION
    REPORT_VERSION = getattr(s, "REPORT_VERSION", "1.0.0")

    storage = build_page()

    if args.export:
        _export(storage, Path(args.export))
        return 0
    if args.preview:
        out = Path(args.preview)
        out.write_text(build_preview(storage), encoding="utf-8")
        print(f"preview written to {out} - open it in a browser",
              file=sys.stderr)
        return 0
    if args.dry_run:
        out = Path("page.html")
        out.write_text(storage, encoding="utf-8")
        print(f"dry run - wrote {out} ({len(storage)} bytes), no request made",
              file=sys.stderr)
        return 0

    print(f"connecting: {describe_settings(s)}", file=sys.stderr)
    cf = Confluence(s)

    if args.test:
        try:
            cf.ping()
        except RuntimeError as exc:
            print(f"FAILED: {exc}", file=sys.stderr)
            return 1
        print("credentials OK, space reachable", file=sys.stderr)
        return 0

    try:
        existing = cf.find()
        if existing:
            cf.update(existing, storage)
            print(f"updated page id={existing['id']} "
                  f"version={existing['version']['number'] + 1}", file=sys.stderr)
        else:
            created = cf.create(storage)
            print(f"created page id={created['id']}", file=sys.stderr)
        print(f"open: {cf.base}/pages/{(existing or created).get('id')}",
              file=sys.stderr)
    except RuntimeError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
