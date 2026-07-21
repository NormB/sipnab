Output website/static/demos/10-multileg.gif
Source demos/common.tape

# One size down from common.tape's FontSize 20: at 1200px that renders a
# 96-column terminal (vs 88), the minimum for a 3-leg B2BUA ladder whose
# widest arrow labels ("INVITE (SDP) (+1 retx)" = 22 chars -> 27-col pipe
# gaps) fit untruncated next to a >= 24-col detail pane.
Set FontSize 19

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
