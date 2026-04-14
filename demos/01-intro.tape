Output website/static/demos/01-intro.gif
Set Shell bash
Set FontSize 20
Set Width 1200
Set Height 700
Set Padding 10
Set TypingSpeed 100ms
Set Theme { "name": "sipnab", "black": "#0a0e14", "red": "#ff6666", "green": "#bae67e", "yellow": "#ffcc66", "blue": "#73d0ff", "magenta": "#d4bfff", "cyan": "#95e6cb", "white": "#cbccc6", "brightBlack": "#707a8c", "brightRed": "#ff6666", "brightGreen": "#bae67e", "brightYellow": "#ffcc66", "brightBlue": "#73d0ff", "brightMagenta": "#d4bfff", "brightCyan": "#95e6cb", "brightWhite": "#f0f0f0", "background": "#0a0e14", "foreground": "#cbccc6", "selectionBackground": "#1f2430", "cursorColor": "#ffcc66" }

# Launch sipnab immediately and hide the command
Hide
Type "sipnab -I tests/pcap-samples/sip-rtp-g711.pcap"
Enter
Sleep 3s
Show

# Now recording starts with the full TUI already rendered
Sleep 4s

# Navigate the call list
Down
Sleep 2s

# Open call flow
Enter
Sleep 6s

# Navigate messages
Down
Sleep 2s
Down
Sleep 2s
Down
Sleep 2s

# Hold on final view
Sleep 6s
