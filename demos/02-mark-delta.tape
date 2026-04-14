Output website/static/demos/02-mark-delta.gif
Set Shell bash
Set FontSize 20
Set Width 1200
Set Height 700
Set Padding 10
Set TypingSpeed 80ms
Set Theme { "name": "sipnab", "black": "#0a0e14", "red": "#ff6666", "green": "#bae67e", "yellow": "#ffcc66", "blue": "#73d0ff", "magenta": "#d4bfff", "cyan": "#95e6cb", "white": "#cbccc6", "brightBlack": "#707a8c", "brightRed": "#ff6666", "brightGreen": "#bae67e", "brightYellow": "#ffcc66", "brightBlue": "#73d0ff", "brightMagenta": "#d4bfff", "brightCyan": "#95e6cb", "brightWhite": "#f0f0f0", "background": "#0a0e14", "foreground": "#cbccc6", "selectionBackground": "#1f2430", "cursorColor": "#ffcc66" }

Type "sipnab -I tests/pcap-samples/SIP_CALL_RTP_G711"
Sleep 5s
Enter
Sleep 4s

# Open call flow
Enter
Sleep 5s

# Mark the INVITE
Type "m"
Sleep 2.5s

# Navigate down to 200 OK
Down
Sleep 800ms
Down
Sleep 800ms
Down
Sleep 800ms
Down
Sleep 800ms

# Pause to show the delta badge
Sleep 5s

# Clear mark
Type "M"
Sleep 2.5s

Escape
Sleep 5s
