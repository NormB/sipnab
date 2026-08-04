# Shared VHS style for every sipnab demo. Each demo tape does:
#   Output website/static/demos/<name>.gif
#   Source demos/common.tape
#   <script...>
# Rendered from the repo root so the terminal cwd resolves tests/pcap-samples/*.
# The `sipnab` these tapes invoke is the one BUILT FROM THIS TREE: demos/Makefile
# prepends target/release to PATH and refuses to render if that binary's version
# disagrees with Cargo.toml. Do not run a tape directly with bare `vhs` -- it
# would pick up whatever sipnab is installed and can silently record an old UI.
# See the Makefile header for the truncated-Method incident that caused this.
# FontFamily MUST be a monospace font that is actually installed (verify with
# `fc-list`). Naming a missing font (e.g. "JetBrains Mono" on a bare box) makes
# ttyd fall back with broken metrics: stretched letter-spacing, clipped glyphs.
Set Shell bash
Set FontFamily "DejaVu Sans Mono"
Set FontSize 20
Set Width 1200
Set Height 700
Set Padding 10
Set TypingSpeed 90ms
Set Framerate 12
Set Theme { "name": "sipnab", "black": "#0a0e14", "red": "#ff6666", "green": "#bae67e", "yellow": "#ffcc66", "blue": "#73d0ff", "magenta": "#d4bfff", "cyan": "#95e6cb", "white": "#cbccc6", "brightBlack": "#707a8c", "brightRed": "#ff6666", "brightGreen": "#bae67e", "brightYellow": "#ffcc66", "brightBlue": "#73d0ff", "brightMagenta": "#d4bfff", "brightCyan": "#95e6cb", "brightWhite": "#f0f0f0", "background": "#0a0e14", "foreground": "#cbccc6", "selectionBackground": "#1f2430", "cursorColor": "#ffcc66" }
