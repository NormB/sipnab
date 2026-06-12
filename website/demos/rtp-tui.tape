# sipnab RTP Quality TUI Demo
# Shows: call list → call flow with selectable RTP bar → stream detail → streams tab

Output website/demos/08-rtp-tui.gif
Set Theme "Ayu Mirage"
Set FontFamily "JetBrains Mono"
Set FontSize 13
Set Width 1400
Set Height 800
Set Padding 8
Set Framerate 10

Hide
Type "cd ~/sipnab && export PATH=$PWD/target/release:$PATH"
Enter
Sleep 500ms
Show

Type "sipnab -I tests/pcap-samples/voipshark-normal-call.pcap"
Enter
Sleep 3s

# Navigate to INVITE dialog
Down Down Down Down Down Down Down Down Down
Sleep 1.5s

# Enter call flow
Enter
Sleep 2s

# Scroll down past SIP messages to the RTP bar
Down Down Down Down Down Down Down Down
Sleep 2s

# Select the RTP bar — it's highlighted
Down
Sleep 1.5s

# Press Enter to drill into RTP Stream Detail
Enter
Sleep 3s

# Scroll down to see quality intervals and sparklines
Down Down Down Down Down
Sleep 2s

# Esc back to call flow (not stream list!)
Escape
Sleep 2s

# Press 'r' to jump to RTP Streams tab
Type "r"
Sleep 2s

# Navigate streams
Down Down
Sleep 1.5s

# Enter stream detail from stream list
Enter
Sleep 3s

Sleep 1s
