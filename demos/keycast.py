#!/usr/bin/env python3
"""Keycast timeline generator for sipnab VHS demos.

VHS (0.11) has no built-in keystroke display, so the "See It In Action" TUI
GIFs never showed which keys drove them. This tool parses a `.tape` and emits a
GIF-relative timeline of keycap badges — one entry per visible keypress, with a
start/end time measured in the *rendered* GIF's clock (not the tape clock).

The load-bearing subtlety: a tape's setup commands run inside a `Hide`/`Show`
block and never appear in the GIF. The GIF's t=0 is the `Show`, so badge times
must be accumulated only while output is visible. Events emitted during `Hide`
are dropped.

    ./keycast.py demos/04-filter.tape        # print the timeline
    ./keycast.py --self-test                 # run built-in checks

The emitted timeline feeds an ffmpeg overlay pass (separate step) that draws
each badge onto the GIF for its [start, end) window.
"""

from __future__ import annotations

import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

# Default per-key dwell: how long a discrete keycap badge stays up, unless the
# next badge starts sooner (then it's clipped so badges never overlap).
BADGE_DWELL_S = 0.8
# VHS executes a discrete key quickly; model the clock cost of one keypress.
KEY_STEP_S = 0.1
DEFAULT_TYPING_SPEED_S = 0.05  # VHS default; overridden by `Set TypingSpeed`.

# Discrete keys VHS understands that we render as a badge. Value = display
# label. Arrows (U+2190..2193) are present in DejaVu Sans; everything else uses
# a word so no glyph is missing (tofu) in the ffmpeg drawtext font.
KEY_LABELS = {
    "Enter": "Enter",
    "Down": "↓",
    "Up": "↑",
    "Left": "←",
    "Right": "→",
    "Tab": "Tab",
    "Escape": "Esc",
    "Space": "Space",
    "Backspace": "Bksp",
}


@dataclass
class Badge:
    label: str  # what to draw in the keycap
    start: float  # GIF-relative seconds
    end: float

    def __repr__(self) -> str:
        return f"[{self.start:6.2f}s -> {self.end:6.2f}s] {self.label!r}"


def _parse_duration(tok: str) -> float:
    """VHS duration token -> seconds. '3s', '500ms', '1.2s', bare number = s."""
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(ms|s)?", tok.strip())
    if not m:
        raise ValueError(f"bad duration {tok!r}")
    val = float(m.group(1))
    return val / 1000.0 if m.group(2) == "ms" else val


def parse_tape(path: Path, typing_speed_s: float = DEFAULT_TYPING_SPEED_S) -> list[Badge]:
    """Parse a tape (following one level of `Source`) into GIF badge events."""
    badges: list[Badge] = []
    gif_clock = 0.0
    hidden = False
    ts = typing_speed_s

    def emit(label: str, dwell: float) -> None:
        # Clip the previous badge so it ends when this one starts (no overlap).
        if badges and badges[-1].end > gif_clock:
            badges[-1].end = gif_clock
        badges.append(Badge(label, gif_clock, gif_clock + dwell))

    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("Source "):
            # Pull TypingSpeed out of the sourced file (usually common.tape).
            inc = (path.parent / Path(line[len("Source "):].strip()).name)
            if inc.exists():
                for il in inc.read_text().splitlines():
                    ms = re.match(r"\s*Set\s+TypingSpeed\s+(\S+)", il)
                    if ms:
                        ts = _parse_duration(ms.group(1))
            continue

        if line == "Hide":
            hidden = True
            continue
        if line == "Show":
            hidden = False
            continue

        ms = re.match(r"Set\s+TypingSpeed\s+(\S+)", line)
        if ms:
            ts = _parse_duration(ms.group(1))
            continue

        ms = re.match(r"Sleep\s+(\S+)", line)
        if ms:
            if not hidden:
                gif_clock += _parse_duration(ms.group(1))
            continue

        ms = re.match(r'Type\s+"(.*)"$', line)
        if ms:
            text = ms.group(1)
            dur = max(len(text) * ts, 0.3)
            if not hidden:
                emit(text, dur)
                gif_clock += dur
            continue

        # Discrete key (possibly repeated count, e.g. "Down 3").
        ms = re.match(r"([A-Za-z]+(?:\+[A-Za-z]+)?)(?:\s+(\d+))?$", line)
        if ms and (ms.group(1) in KEY_LABELS or "+" in ms.group(1) or len(ms.group(1)) == 1):
            key, count = ms.group(1), int(ms.group(2) or 1)
            label = KEY_LABELS.get(key, key)
            for _ in range(count):
                if not hidden:
                    emit(label, BADGE_DWELL_S)
                    gif_clock += KEY_STEP_S
            continue

    return badges


# Font with the arrow glyphs + a keycap look. DejaVu Sans is present on the
# demo box (it's also the terminal font family).
BADGE_FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def _esc_drawtext(s: str) -> str:
    """Escape a literal string for ffmpeg drawtext `text=`."""
    return s.replace("\\", "\\\\").replace(":", r"\:").replace("'", r"\'")


def build_filter(badges: list[Badge], fontsize: int = 26) -> str:
    """A filtergraph that draws each badge as a keycap in the lower-right,
    visible only during its [start, end) window."""
    chains = []
    for b in badges:
        if b.end <= b.start:
            continue
        en = f"between(t,{b.start:.3f},{b.end:.3f})"
        chains.append(
            f"drawtext=fontfile='{BADGE_FONT}':text='{_esc_drawtext(b.label)}':"
            f"fontsize={fontsize}:fontcolor=0x0a0e14:box=1:boxcolor=0xffcc66@0.92:"
            f"boxborderw=14:x=w-tw-40:y=h-th-36:enable='{en}'"
        )
    return ",".join(chains) if chains else "null"


def overlay(in_gif: Path, out_gif: Path, tape: Path) -> int:
    """Composite the tape's keycap badges onto in_gif -> out_gif.

    Two-pass palette encode: ffmpeg 7 + a single-pass GIF filtergraph
    intermittently emits a 0-byte GIF, so we generate a palette then apply it
    (this is the same trap the VHS render works around)."""
    import subprocess
    import tempfile

    badges = parse_tape(tape)
    filt = build_filter(badges)
    with tempfile.TemporaryDirectory() as d:
        pal = Path(d) / "pal.png"
        r = subprocess.run(
            ["ffmpeg", "-y", "-i", str(in_gif),
             "-vf", f"{filt},palettegen=stats_mode=diff", str(pal)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            sys.stderr.write(r.stderr[-2000:])
            return r.returncode
        r = subprocess.run(
            ["ffmpeg", "-y", "-i", str(in_gif), "-i", str(pal),
             "-lavfi", f"{filt}[x];[x][1:v]paletteuse=dither=bayer",
             # Force the GIF muxer so a non-".gif" output name (e.g. a temp
             # "foo.gif.new") still encodes correctly.
             "-f", "gif", str(out_gif)],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            sys.stderr.write(r.stderr[-2000:])
            return r.returncode
    sz = out_gif.stat().st_size if out_gif.exists() else 0
    if sz == 0:
        sys.stderr.write("ERROR: produced a 0-byte GIF\n")
        return 1
    print(f"wrote {out_gif} ({sz} bytes, {len(badges)} badges)")
    return 0


def _self_test() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as d:
        common = Path(d) / "common.tape"
        common.write_text("Set TypingSpeed 90ms\n")
        tape = Path(d) / "t.tape"
        tape.write_text(
            "Output x.gif\n"
            "Source common.tape\n"
            "Hide\n"
            'Type "sipnab -I x.pcap"\n'  # setup, hidden -> no badge
            "Enter\n"
            "Sleep 3s\n"
            "Show\n"  # GIF starts here, gif_clock = 0
            "Sleep 2s\n"  # -> 2.0
            "Down 2\n"  # two ↓ badges at 2.0 and 2.1
            "Enter\n"  # ⏎ at 2.2
            "Sleep 1s\n"
        )
        badges = parse_tape(tape)
        if not all(b.label != "sipnab -I x.pcap" for b in badges): raise AssertionError("hidden Type leaked")
        labels = [b.label for b in badges]
        if labels != ["↓", "↓", "Enter"]: raise AssertionError(labels)
        if not abs(badges[0].start - 2.0) < 1e-9: raise AssertionError(badges[0])
        # First ↓ is clipped by the second at 2.1.
        if not abs(badges[0].end - 2.1) < 1e-9: raise AssertionError(badges[0])
        if not abs(badges[2].start - 2.2) < 1e-9: raise AssertionError(badges[2])
    print("self-test OK")


def main(argv: list[str]) -> int:
    if "--self-test" in argv:
        _self_test()
        return 0
    if len(argv) == 5 and argv[1] == "overlay":
        # keycast.py overlay <in.gif> <out.gif> <tape>
        return overlay(Path(argv[2]), Path(argv[3]), Path(argv[4]))
    if len(argv) != 2:
        print(__doc__)
        return 2
    for b in parse_tape(Path(argv[1])):
        print(b)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
