Output website/static/demos/07-rtp-cli.gif
Source demos/common.tape
Set Framerate 8

# Headless CLI: JSON dialogs, problem detection, and a full call report.
Type "# Emit every SIP dialog as JSON"
Enter
Sleep 700ms
Type "sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap --json 2>/dev/null | head -8"
Enter
Sleep 3.5s
Type "# Surface only the calls with problems"
Enter
Sleep 700ms
Type "sipnab -N -I tests/pcap-samples/sip-rtp-g711.pcap --problems 2>/dev/null | head -12"
Enter
Sleep 3.5s
Type "# Print a detailed call report"
Enter
Sleep 700ms
Type "sipnab -N -I tests/pcap-samples/DTMFsipinfo.pcap --report 2>/dev/null | head -20"
Enter
Sleep 4s
