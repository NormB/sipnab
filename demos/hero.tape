Output demos/.hero-tmp.gif
Set Shell bash
Set FontSize 20
Set Width 1200
Set Height 700
Set Padding 10
Set Theme { "name": "sipnab", "black": "#0a0e14", "red": "#ff6666", "green": "#bae67e", "yellow": "#ffcc66", "blue": "#73d0ff", "magenta": "#d4bfff", "cyan": "#95e6cb", "white": "#cbccc6", "brightBlack": "#707a8c", "brightRed": "#ff6666", "brightGreen": "#bae67e", "brightYellow": "#ffcc66", "brightBlue": "#73d0ff", "brightMagenta": "#d4bfff", "brightCyan": "#95e6cb", "brightWhite": "#f0f0f0", "background": "#0a0e14", "foreground": "#cbccc6", "selectionBackground": "#1f2430", "cursorColor": "#ffcc66" }

# Launch the current TUI on a sample capture and screenshot its landing screen
# (the sortable call-list view — the first thing the tool shows).
Hide
Type "sipnab -I tests/pcap-samples/sipp-branch-scenario.pcapng"
Enter
Sleep 5s
Show
Sleep 1.5s
Screenshot website/static/demos/hero-static.png
Sleep 0.3s
