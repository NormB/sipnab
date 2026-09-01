Output website/static/demos/01-intro.gif
Source demos/common.tape

# Browse SIP dialogs, drill into the call-flow ladder, read parsed detail.
#
# THE SAME capture /analyze offers behind "Load a sample call", so a visitor who
# watches this and then clicks through sees the call they were just shown rather
# than a different one. It is also the richer capture: seven dialogs covering
# Registered, Expired (an unregister by both the Expires header and the Contact
# parameter), Active, Pending and Terminated subscriptions, an OPTIONS ping, and
# the call itself with 600 RTP packets. PII-free by construction -- TEST-NET-1
# addresses, alice and bob at example.com.
#
# The walk down is deliberate rather than filler: it is what puts every dialog
# state on screen. The call is the SEVENTH, so six Downs reach it, and that
# count couples this tape to demos/gen-sample-call.py -- adding a dialog there
# silently retargets this recording at whatever then sits seventh.
Hide
Type "sipnab -I website/static/demos/sample-call.pcap"
Enter
Sleep 3s
Show
Sleep 3.5s
Down
Sleep 0.8s
Down
Sleep 0.8s
Down
Sleep 0.8s
Down
Sleep 0.8s
Down
Sleep 0.8s
Down
Sleep 1.5s
Enter
Sleep 5s
Down
Sleep 1.2s
Down
Sleep 1.2s
Down
Sleep 1.2s
Sleep 4s
