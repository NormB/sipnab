Output website/static/demos/05-file-open.gif
Set Shell bash
Set FontSize 14
Set Width 1200
Set Height 700
Set Padding 10
Set TypingSpeed 40ms
Set Theme { "name": "sipnab", "black": "#0a0e14", "red": "#ff6666", "green": "#bae67e", "yellow": "#ffcc66", "blue": "#73d0ff", "magenta": "#d4bfff", "cyan": "#95e6cb", "white": "#cbccc6", "brightBlack": "#707a8c", "brightRed": "#ff6666", "brightGreen": "#bae67e", "brightYellow": "#ffcc66", "brightBlue": "#73d0ff", "brightMagenta": "#d4bfff", "brightCyan": "#95e6cb", "brightWhite": "#f0f0f0", "background": "#0a0e14", "foreground": "#cbccc6", "selectionBackground": "#1f2430", "cursorColor": "#ffcc66" }

# Start with one pcap
Type "sipnab -I tests/pcap-samples/sip-rtp-g711.pcap"
Sleep 500ms
Enter
Sleep 2s

# Open file dialog
Type "O"
Sleep 1s

# Type new path
Type "tests/pcap-samples/b2bua-asterisk.pcapng"
Sleep 1s

# Load it
Enter
Sleep 3s

# Show the new data loaded
Down
Sleep 300ms
Down
Sleep 300ms

Sleep 2s
