Output website/static/demos/07-rtp-cli.gif
Source demos/common.tape
Set Framerate 8

# Headless CLI: JSON dialogs, problem detection, and a full call report.
Type "# Every SIP dialog as JSON -- one completed call and four failures"
Enter
Sleep 700ms
Type "sipnab -N -I tests/pcap-samples/sip-problem-call.pcap --json 2>/dev/null | head -8"
Enter
Sleep 3.5s
Type "# Surface only the calls with problems -- the 200 OK call drops out"
Enter
Sleep 700ms
Type "sipnab -N -I tests/pcap-samples/sip-problem-call.pcap --problems 2>/dev/null | head -12"
Enter
Sleep 4s
Type "# Print a detailed call report"
Enter
Sleep 700ms
Type "sipnab -N -I tests/pcap-samples/DTMFsipinfo.pcap --report 2>/dev/null | head -20"
Enter
Sleep 4s
