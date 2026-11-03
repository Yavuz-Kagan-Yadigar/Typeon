#!/usr/bin/env python3
"""Converts the Android vector drawables of the Typeon app into plain SVG.

The desktop client draws the same icons as the phone, so the vector paths are
taken from the app's own drawables instead of a different icon set. Android's
`<vector>` and SVG's `<path>` describe the same geometry; only the attribute
names differ.

Run from the repository root:

    python3 tools/import_icons.py
"""

from __future__ import annotations

import pathlib
import re
import xml.etree.ElementTree as ET

ANDROID = "{http://schemas.android.com/apk/res/android}"
ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "p2p_messenger_android/app/src/main/res/drawable"
TARGET = ROOT / "Linux-qt6/data/icons"

# The Android drawables that are used by the desktop UI.
WANTED = [
    "ic_attach",
    "ic_attachment_file",
    "ic_camera",
    "ic_call",
    "ic_chat_list",
    "ic_close",
    "ic_eraser",
    "ic_expand_more",
    "ic_mic",
    "ic_mic_off",
    "ic_pause",
    "ic_pen",
    "ic_play",
    "ic_reply",
    "ic_send_cloud",
    "ic_skip_back",
    "ic_skip_forward",
    "ic_status_delivered",
    "ic_status_error",
    "ic_status_pending",
    "ic_status_sent",
    "ic_videocam",
    "qr_frame",
]

# Icons the phone takes from the platform (the bottom navigation); the
# Material paths are written out here.
EXTRA = {
    "ic_nav_chats": [
        "M20 2H4c-1.1 0-1.99.9-1.99 2L2 22l4-4h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2z",
    ],
    "ic_nav_contacts": [
        "M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 "
        "2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 "
        "3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 1.97 "
        "1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z",
    ],
    "ic_nav_settings": [
        "M3 17v2h6v-2H3zM3 5v2h10V5H3zm10 16v-2h8v-2h-8v-2h-2v6h2zM7 9v2H3v2h4v2h2V9H7zm14 "
        "4v-2H11v2h10zm-6-4h2V7h4V5h-4V3h-2v6z",
    ],
    "ic_menu": ["M3 18h18v-2H3v2zm0-5h18v-2H3v2zm0-7v2h18V6H3z"],
    "ic_search": [
        "M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 "
        "5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 "
        "19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 "
        "9.5 14z",
    ],
    "ic_back": ["M20 11H7.83l5.59-5.59L12 4l-8 8 8 8 1.41-1.41L7.83 13H20v-2z"],
    "ic_more_vert": [
        "M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 "
        "2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z",
    ],
    "ic_add": ["M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"],
    "ic_person": [
        "M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 "
        "1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z",
    ],
    "ic_group": [
        "M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 "
        "0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 "
        "1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5zm8 0c-.29 0-.62.02-.97.05 1.16.84 1.97 "
        "1.97 1.97 3.45V19h6v-2.5c0-2.33-4.67-3.5-7-3.5z",
    ],
    "ic_qr": [
        "M3 11h8V3H3v8zm2-6h4v4H5V5zM3 21h8v-8H3v8zm2-6h4v4H5v-4zM13 3v8h8V3h-8zm6 6h-4V5h4v4zm0 "
        "10h2v2h-2zm-4 0h2v2h-2zm-2 2h2v2h-2zm-2-2h2v2H9zm-2 2h2v2H7zm4-6h2v2h-2zm2 2h2v2h-2zm2 "
        "2h2v2h-2zm-2 2h2v2h-2z",
    ],
    "ic_link": [
        "M3.9 12c0-1.71 1.39-3.1 3.1-3.1h4V7H7c-2.76 0-5 2.24-5 5s2.24 5 5 5h4v-1.9H7c-1.71 "
        "0-3.1-1.39-3.1-3.1zM8 13h8v-2H8v2zm9-6h-4v1.9h4c1.71 0 3.1 1.39 3.1 3.1s-1.39 "
        "3.1-3.1 3.1h-4V17h4c2.76 0 5-2.24 5-5s-2.24-5-5-5z",
    ],
    "ic_info": [
        "M11 7h2v2h-2zm0 4h2v6h-2zm1-9C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 "
        "2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8z",
    ],
    "ic_warning": [
        "M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z",
    ],
    "ic_lock": [
        "M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 "
        "2-.9 2-2V10c0-1.1-.9-2-2-2zm-6 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zm3.1-9H8.9V6c0-1.71 "
        "1.39-3.1 3.1-3.1s3.1 1.39 3.1 3.1v2z",
    ],
    "ic_download": [
        "M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z",
    ],
    "ic_key": [
        "M12.65 10C11.83 7.67 9.61 6 7 6c-3.31 0-6 2.69-6 6s2.69 6 6 6c2.61 0 4.83-1.67 "
        "5.65-4H17v4h4v-4h2v-4H12.65zM7 14c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z",
    ],
    "ic_check": ["M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"],
    "ic_send": ["M2.01 21L23 12 2.01 3 2 10l15 2-15 2z"],
}


# The desktop draws every icon as a mask (the widget's text colour), so the
# concrete colour does not matter — but the placeholders have to resolve to
# something an SVG renderer understands.
COLOURS = {
    "@android:color/white": "#ffffff",
    "@android:color/black": "#000000",
    "@android:color/transparent": "none",
}


def colour(value: str | None) -> str:
    if value is None:
        return "none"
    if value in COLOURS:
        return COLOURS[value]
    if value.startswith("?"):
        # A theme attribute (`?attr/colorOnSurface`) — the mask makes the
        # colour irrelevant, only the alpha channel matters.
        return "#ffffff"
    return value


def convert(vector: ET.Element) -> str:
    """Turns an Android `<vector>` into the body of an SVG document."""
    width = vector.get(f"{ANDROID}viewportWidth", "24")
    height = vector.get(f"{ANDROID}viewportHeight", "24")
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}">'
    ]
    for path in vector.findall("path"):
        data = path.get(f"{ANDROID}pathData")
        if not data:
            continue
        fill = colour(path.get(f"{ANDROID}fillColor", "#000000"))
        stroke = path.get(f"{ANDROID}strokeColor")
        stroke = colour(stroke) if stroke else None
        stroke_width = path.get(f"{ANDROID}strokeWidth")
        attributes = [f'd="{data}"']
        if stroke:
            attributes.append(f'fill="none"')
            attributes.append(f'stroke="{stroke}"')
            if stroke_width:
                attributes.append(f'stroke-width="{stroke_width}"')
            attributes.append('stroke-linecap="round"')
            attributes.append('stroke-linejoin="round"')
        else:
            attributes.append(f'fill="{fill}"')
        parts.append("  <path " + " ".join(attributes) + "/>")
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main() -> None:
    TARGET.mkdir(parents=True, exist_ok=True)
    written = 0

    for name in WANTED:
        source = SOURCE / f"{name}.xml"
        if not source.exists():
            print(f"skipping missing {source}")
            continue
        tree = ET.parse(source)
        svg = convert(tree.getroot())
        (TARGET / f"{name}.svg").write_text(svg)
        written += 1

    for name, paths in EXTRA.items():
        body = "\n".join(f'  <path fill="#ffffff" d="{d}"/>' for d in paths)
        svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">\n'
            f"{body}\n"
            "</svg>\n"
        )
        (TARGET / f"{name}.svg").write_text(svg)
        written += 1

    print(f"wrote {written} icons to {TARGET}")


if __name__ == "__main__":
    main()
