Output website/static/demos/04-filter.gif
Source demos/common.tape

# Live incremental search: narrow a 12-dialog list by typing, matching
# To user ("2302" -> the one call to that extension) then dialog state
# ("FAILED" -> just the failed dialogs). NOTE: the search has a full-text
# fallback over raw messages, so method names like "INVITE" match every
# dialog via Allow: headers and never narrow — site_journey_test's
# every_typed_search_query_narrows_the_demo_pcap gate keeps these queries
# honest against the pcap.
Hide
Type "sipnab -I tests/pcap-samples/b2bua-asterisk.pcapng"
Enter
Sleep 3s
Show
Sleep 3s
Type "/"
Sleep 1.2s
Type "2302"
Sleep 3s
Escape
Sleep 1.5s
Type "/"
Sleep 1.2s
Type "FAILED"
Sleep 3s
Escape
Sleep 2s
