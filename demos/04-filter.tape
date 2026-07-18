Output website/static/demos/04-filter.gif
Source demos/common.tape

# Live incremental search: narrow a 12-dialog list by typing, matching
# method / From / To / Call-ID in real time.
Hide
Type "sipnab -I tests/pcap-samples/b2bua-asterisk.pcapng"
Enter
Sleep 3s
Show
Sleep 3s
Type "/"
Sleep 1.2s
Type "INVITE"
Sleep 3s
Escape
Sleep 1.5s
Type "/"
Sleep 1.2s
Type "REGIS"
Sleep 3s
Escape
Sleep 2s
