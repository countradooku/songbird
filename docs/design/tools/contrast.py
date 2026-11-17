#!/usr/bin/env python3
"""WCAG 2.2 contrast check for Songbird's colour tokens.

Reads apps/ui/theme.json (light, dark) and the high-contrast overrides in
apps/ui/src/theming.rs, so it always checks what the app ships. Every pair
below is a real foreground/background combination used by src/ui or a spec
in docs/design. Thresholds:

  text  4.5:1  (WCAG 1.4.3, normal text)
  large 3:1    (WCAG 1.4.3, >= 18.66px bold or 24px regular)
  ui    3:1    (WCAG 1.4.11, icons, control boundaries, focus rings, ticks)
  info  none   (decorative; reported, never a failure)

Usage:  python3 docs/design/tools/contrast.py [--fails] [--markdown]
Exit status 1 when any pair fails, so CI can run it.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
THEME = ROOT / "apps/ui/theme.json"
THEMING = ROOT / "apps/ui/src/theming.rs"

# (foreground token, background token, kind, where it is used)
PAIRS = [
    ("foreground", "background", "text", "body text on pages"),
    ("foreground", "card", "text", "row titles, field text"),
    ("foreground", "popover", "text", "sheet and dialog text"),
    ("card-foreground", "card", "text", "card text"),
    ("popover-foreground", "popover", "text", "popover text"),
    ("foreground", "accent", "text", "row text while hovered/pressed"),
    ("foreground", "sidebar-accent", "text", "rail item hovered"),
    ("muted-foreground", "background", "text", "subtitles, tab labels"),
    ("muted-foreground", "card", "text", "row subtitles, values, placeholders"),
    ("muted-foreground", "popover", "text", "sheet secondary text"),
    ("muted-foreground", "secondary", "text", "search placeholder, unselected chip"),
    ("muted-foreground", "muted", "text", "muted surfaces"),
    ("muted-foreground", "sidebar", "text", "rail labels"),
    ("muted-foreground", "chat-bg", "text", "date chips, system lines in chat"),
    ("primary-foreground", "primary", "text", "primary button, unread badge"),
    ("background", "muted-foreground", "text", "muted chat unread badge"),
    ("secondary-foreground", "secondary", "text", "secondary button, tag"),
    ("accent-foreground", "accent", "text", "selected chip"),
    ("primary", "background", "text", "ghost/outline button label"),
    ("primary", "card", "text", "ghost button inside a card"),
    ("primary", "accent", "ui", "selected tab icon, icon tile, empty-state glyph"),
    ("destructive", "background", "text", "danger row label"),
    ("destructive", "card", "text", "danger row label in a group"),
    ("destructive-foreground", "destructive", "text", "danger button"),
    ("sidebar-foreground", "sidebar", "text", "rail text"),
    ("sidebar-accent-foreground", "sidebar-accent", "text", "rail selection"),
    ("bubble-out-foreground", "bubble-out", "text", "outgoing message"),
    ("bubble-in-foreground", "bubble-in", "text", "incoming message"),
    ("bubble-meta", "bubble-out", "text", "time and sent/delivered ticks, outgoing"),
    ("bubble-meta", "bubble-in", "text", "time, incoming"),
    ("link", "bubble-in", "text", "link in incoming bubble"),
    ("link", "bubble-out", "text", "link in outgoing bubble"),
    ("link", "background", "text", "link on a page"),
    ("mention", "bubble-in", "text", "@mention, incoming"),
    ("mention", "bubble-out", "text", "@mention, outgoing"),
    ("foreground", "highlight", "text", "search match highlight"),
    ("foreground", "warning-bg", "text", "warning banner text"),
    ("foreground", "info-bg", "text", "info / secure banner text"),
    ("warning", "warning-bg", "ui", "warning banner icon"),
    ("destructive", "warning-bg", "ui", "danger banner icon"),
    ("link", "info-bg", "ui", "info banner icon"),
    ("primary", "info-bg", "ui", "secure banner icon"),
    ("success-foreground", "success", "text", "success badge"),
    ("success", "background", "ui", "success icon on page"),
    ("warning", "background", "text", "warning text on page"),
    ("call-foreground", "call-bg", "text", "call screen text"),
    ("call-foreground", "call-accept", "ui", "accept glyph"),
    ("call-foreground", "call-decline", "ui", "decline glyph"),
    ("call-accept", "call-bg", "ui", "accept button on call screen"),
    ("call-decline", "call-bg", "ui", "decline button on call screen"),
    ("background", "foreground", "text", "toast"),
    ("tick-read", "bubble-out", "ui", "read tick"),
    ("tick-read", "bubble-in", "ui", "played mark in incoming voice note"),
    ("destructive", "bubble-out", "ui", "failed tick"),
    ("online", "card", "ui", "presence dot"),
    ("online", "background", "ui", "presence dot on page"),
    ("input", "card", "ui", "field border"),
    ("input", "background", "ui", "toggle track off, on page"),
    ("card", "input", "ui", "toggle knob on off track"),
    ("card", "primary", "ui", "toggle knob on on track"),
    ("primary", "background", "ui", "toggle on / primary button boundary"),
    ("ring", "background", "ui", "focus ring"),
    ("ring", "card", "ui", "focus ring in a group"),
    ("input", "popover", "ui", "sheet grabber"),
    ("border", "background", "info", "hairline separators (decorative)"),
    ("border", "card", "info", "group border (decorative)"),
    ("bubble-in", "chat-bg", "info", "incoming bubble edge (shape is not needed to read)"),
    ("bubble-out", "chat-bg", "info", "outgoing bubble edge"),
] + [(f"avatar-foreground", f"avatar-{i}", "text", "avatar initials") for i in range(1, 9)]

THRESH = {"text": 4.5, "large": 3.0, "ui": 3.0, "info": 0.0}


def parse_hc():
    src = THEMING.read_text()
    out = {}
    for mode, name in (("light", "HIGH_CONTRAST_LIGHT"), ("dark", "HIGH_CONTRAST_DARK")):
        m = re.search(name + r".*?=\s*&\[(.*?)\];", src, re.S)
        out[mode] = dict(re.findall(r'\("([\w-]+)",\s*"(#[0-9A-Fa-f]{6,8})"\)', m.group(1))) if m else {}
    return out


def rgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) / 255 for i in (0, 2, 4))


def lum(h):
    def ch(c):
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    r, g, b = (ch(c) for c in rgb(h))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def themes():
    base = json.loads(THEME.read_text())["cssVars"]
    hc = parse_hc()
    return {
        "light": base["light"],
        "dark": base["dark"],
        "hc-light": {**base["light"], **hc["light"]},
        "hc-dark": {**base["dark"], **hc["dark"]},
    }


def main():
    only_fails = "--fails" in sys.argv
    md = "--markdown" in sys.argv
    fails = 0
    if md:
        print("| Theme | Foreground | Background | Ratio | Needs | Result | Used for |")
        print("| --- | --- | --- | --- | --- | --- | --- |")
    for name, t in themes().items():
        for fg, bg, kind, where in PAIRS:
            if fg not in t or bg not in t:
                continue
            r = ratio(t[fg][:7], t[bg][:7])
            need = THRESH[kind]
            if kind == "info":
                res = "info"
            elif r >= need:
                res = "pass"
            else:
                res = "FAIL"
                fails += 1
            if only_fails and res != "FAIL":
                continue
            if md:
                print(f"| {name} | `{fg}` {t[fg]} | `{bg}` {t[bg]} | {r:.2f} | {need or '—'} ({kind}) | {res} | {where} |")
            else:
                print(f"{name:9} {res:5} {r:5.2f}:1 need {need:<3} {kind:4} {fg} on {bg} ({where})")
    print(f"\n{fails} failing pair(s)" if not md else f"\n**{fails} failing pair(s).**")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
