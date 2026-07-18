Output demos/.hero-tmp.gif
Source demos/common.tape

# Hero still: a complete REGISTER -> INVITE -> re-INVITE(hold) -> BYE lifecycle
# with real bidirectional G.711 media (PII-free: alice/bob @ example.com,
# loopback SDP). The port range spans SIP (5080/5082) + RTP (5084-5099) so the
# media streams associate with the call. Land on the list, drill into the
# call-flow ladder, reveal the RTP media line, and screenshot.
Hide
Type "sipnab -I tests/pcap-samples/register-invite-reinvite-bye.pcap --portrange 5080-5099"
Enter
Sleep 4s
Down
Sleep 0.5s
Enter
Sleep 1s
Ctrl+R
Show
Sleep 1.5s
Screenshot website/static/demos/hero-static.png
Sleep 0.3s
