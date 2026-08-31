Output demos/.hero-tmp.gif
Source demos/common.tape

# Hero still: THE SAME capture /analyze offers behind "Load a sample call", so a
# visitor who watches this and then clicks through sees the call they were just
# shown rather than a different one. It is also the richer capture: seven
# dialogs covering Registered, Expired (an unregister), Active, Pending and
# Terminated subscriptions, an OPTIONS ping and the call itself, with 600 RTP
# packets. PII-free by construction -- TEST-NET-1 addresses, alice/bob at
# example.com.
#
# The call is the SEVENTH dialog, so six Downs reach it. That count is the
# whole reason this tape and the capture generator must move together: adding a
# dialog to demos/gen-sample-call.py silently retargets this screenshot at
# whatever now sits in seventh place.
Hide
Type "sipnab -I website/static/demos/sample-call.pcap"
Enter
Sleep 4s
Down
Down
Down
Down
Down
Down
Sleep 0.5s
Enter
Sleep 1s
Ctrl+R
Show
Sleep 1.5s
Screenshot website/static/demos/hero-static.png
Sleep 0.3s
