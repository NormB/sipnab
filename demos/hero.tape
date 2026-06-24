Output demos/.hero-tmp.gif
Set Shell bash
Set FontSize 20
Set Width 1200
Set Height 700
Set Padding 10
Set Theme { "name": "sipnab", "black": "#0a0e14", "red": "#ff6666", "green": "#bae67e", "yellow": "#ffcc66", "blue": "#73d0ff", "magenta": "#d4bfff", "cyan": "#95e6cb", "white": "#cbccc6", "brightBlack": "#707a8c", "brightRed": "#ff6666", "brightGreen": "#bae67e", "brightYellow": "#ffcc66", "brightBlue": "#73d0ff", "brightMagenta": "#d4bfff", "brightCyan": "#95e6cb", "brightWhite": "#f0f0f0", "background": "#0a0e14", "foreground": "#cbccc6", "selectionBackground": "#1f2430", "cursorColor": "#ffcc66" }

# Launch the TUI on a complete registered-then-call lifecycle capture
# (REGISTER -> INVITE -> re-INVITE(hold) -> BYE; all PII-free: alice/bob @
# example.com, RFC 5737 SDP). Land on the dialog list, then drill into the call
# dialog's call-flow ladder so the hero shows the whole call lifecycle at a
# glance: INVITE/180/200/ACK -> re-INVITE/200/ACK -> BYE/200, with the decoded
# SIP message in the detail pane.
Hide
Type "sipnab -I tests/pcap-samples/register-invite-reinvite-bye.pcap --portrange 5080-5082"
Enter
Sleep 4s
Down
Sleep 0.5s
Enter
Show
Sleep 1.5s
Screenshot website/static/demos/hero-static.png
Sleep 0.3s
