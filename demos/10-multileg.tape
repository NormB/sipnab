Output website/static/demos/10-multileg.gif
Source demos/common.tape

# Multi-leg / B2BUA: select the INVITE call leg, toggle extended flow (x) to
# stitch the correlated back-to-back-UA legs into one ladder.
Hide
Type "sipnab -I tests/pcap-samples/b2bua-asterisk.pcapng"
Enter
Sleep 3s
Show
Sleep 2.5s
Down
Down
Down
Down
Down
Sleep 1.5s
Enter
Sleep 3s
Type "x"
Sleep 4.5s
Sleep 2s
