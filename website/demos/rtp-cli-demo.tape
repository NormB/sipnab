# sipnab RTP Quality CLI Demo

Output website/demos/07-rtp-cli.gif
Set Theme "Ayu Mirage"
Set FontFamily "JetBrains Mono"
Set FontSize 14
Set Width 1200
Set Height 650
Set Padding 12
Set Framerate 10

Hide
Type "cd /Users/gator/Development/sipnab && export PATH=$PWD/target/release:$PATH"
Enter
Sleep 500ms
Show

# Command 1: Show SIP dialogs with JSON
Type "# Analyze a pcap — show all SIP dialogs as JSON"
Enter
Sleep 800ms
Type "sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap --json 2>/dev/null | head -8"
Enter
Sleep 4s

# Command 2: Filter failed calls
Type ""
Enter
Type "# Find problematic calls with quality issues"
Enter
Sleep 800ms
Type "sipnab -N -I tests/pcap-samples/voipshark-normal-call.pcap --problems 2>/dev/null | head -12"
Enter
Sleep 4s

# Command 3: Generate report
Type ""
Enter
Type "# Generate a detailed call report"
Enter
Sleep 800ms
Type "sipnab -N -I tests/pcap-samples/voipshark-dtmf.pcap --report 2>/dev/null | head -20"
Enter
Sleep 5s

Sleep 2s
