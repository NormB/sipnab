# Shared VHS style for every sipnab demo. Each demo tape does:
#   Output website/static/demos/<name>.gif
#   Source demos/common.tape
#   <script...>
# Rendered from the repo root against the installed `sipnab` (0.5.x) so the
# terminal cwd resolves tests/pcap-samples/*. See demos/Makefile.
Set Shell bash
Set FontFamily "JetBrains Mono"
Set FontSize 16
Set Width 1200
Set Height 720
Set Padding 14
Set TypingSpeed 90ms
Set Framerate 12
Set Theme { "name": "sipnab", "black": "#0a0e14", "red": "#ff6666", "green": "#bae67e", "yellow": "#ffcc66", "blue": "#73d0ff", "magenta": "#d4bfff", "cyan": "#95e6cb", "white": "#cbccc6", "brightBlack": "#707a8c", "brightRed": "#ff6666", "brightGreen": "#bae67e", "brightYellow": "#ffcc66", "brightBlue": "#73d0ff", "brightMagenta": "#d4bfff", "brightCyan": "#95e6cb", "brightWhite": "#f0f0f0", "background": "#0a0e14", "foreground": "#cbccc6", "selectionBackground": "#1f2430", "cursorColor": "#ffcc66" }
