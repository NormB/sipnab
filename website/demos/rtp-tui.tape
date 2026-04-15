# sipnab RTP Quality TUI Demo
# Shows: call list → call flow with RTP bars → RTP streams tab

Output website/demos/08-rtp-tui.gif
Set Theme "Ayu Mirage"
Set FontFamily "JetBrains Mono"
Set FontSize 13
Set Width 1400
Set Height 800
Set Padding 8
Set Framerate 10

Hide
Type "cd /Users/gator/Development/sipnab && export PATH=$PWD/target/release:$PATH"
Enter
Sleep 500ms
Show

Type "sipnab -I tests/pcap-samples/voipshark-normal-call.pcap"
Enter
Sleep 4s

# Navigate to INVITE dialog
Down Down Down Down Down Down
Sleep 2s

# Enter call flow
Enter
Sleep 2s

# Scroll down to see RTP bars
Down Down Down Down Down Down Down Down Down Down Down Down Down Down
Sleep 3s

# Back to list
Escape
Sleep 1s

# Switch to RTP Streams tab
Tab
Sleep 3s

# Navigate streams
Down Down Down
Sleep 3s
