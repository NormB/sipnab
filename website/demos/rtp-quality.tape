# sipnab RTP Quality Analysis Demo

Output website/demos/06-rtp-quality.gif
Set Theme "Ayu Mirage"
Set FontFamily "JetBrains Mono"
Set FontSize 13
Set Width 1400
Set Height 800
Set Padding 8
Set Framerate 10

Hide
Type "cd ~/sipnab"
Enter
Sleep 500ms
Show

Type "./target/release/sipnab -I tests/pcap-samples/voipshark-normal-call.pcap"
Enter
Sleep 4s

# Navigate to INVITE dialog
Down Down Down Down Down Down Down
Sleep 2s

# Enter call flow
Enter
Sleep 2s

# Scroll to see RTP
Down Down Down Down Down Down Down Down Down Down Down Down Down Down
Sleep 3s

# Back to list
Escape
Sleep 1s

# RTP Streams tab
Tab
Sleep 3s

# Navigate streams
Down Down Down
Sleep 4s
