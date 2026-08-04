Output website/static/demos/07-rtp-cli.gif
Source demos/common.tape
Set Framerate 8

# TypingSpeed is overridden here, and it is the only tape that does so.
#
# common.tape sets 90ms, which suits the TUI tapes: they type a handful of
# single keys and the deliberate pace reads as someone driving an interface.
# This tape types three full shell commands of ~80 characters each plus their
# narration, and at 90ms/char that is ~38s of typing before a single Sleep is
# counted. The published recording ran 52s -- three times its siblings, which
# sit between 13s and 19s -- on a homepage that autoplays it.
#
# Worse, the recording that shipped was 16.8s, so it had been cut off two
# thirds of the way through and nobody could see the last command finish. The
# render was truncated, not the tape.
#
# 35ms keeps the typing legible while bringing the whole tape back in line with
# the others. The narration lines are shortened for the same reason: they are
# captions, and a caption that takes six seconds to appear is not a caption.
Set TypingSpeed 35ms

# Headless CLI: JSON dialogs, problem detection, and a full call report.
Type "# Every SIP dialog as JSON"
Enter
Sleep 500ms
Type "sipnab -N -I tests/pcap-samples/sip-problem-call.pcap --json 2>/dev/null | head -8"
Enter
Sleep 3s
Type "# Only the calls with problems -- the 200 OK drops out"
Enter
Sleep 500ms
Type "sipnab -N -I tests/pcap-samples/sip-problem-call.pcap --problems 2>/dev/null | head -12"
Enter
Sleep 3.5s
Type "# A detailed call report"
Enter
Sleep 500ms
Type "sipnab -N -I tests/pcap-samples/DTMFsipinfo.pcap --report 2>/dev/null | head -20"
Enter
Sleep 3.5s
