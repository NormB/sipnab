# SIP parameters

Every SIP URI parameter, header-field parameter and option tag in the IANA
registry, with the RFC that defines it and whether sipnab parses it today.

Built from the IANA registries directly, the same way
[sip-response-codes.md](sip-response-codes.md) and [sip-methods.md](sip-methods.md)
were, so the tables move when IANA does rather than when someone remembers.

## What sipnab parses

**Three parameters, deliberately stated conservatively.** `branch` (top `Via`),
`tag` (`From`/`To`) and `expires` (`Contact` parameter, falling back to the
`Expires` header).

An earlier draft of this page computed the column by grepping the source for
each parameter name, which reported 41 of 204. That number was wrong and
flattering: `m`, `code`, `alg` and `count` all appear in unrelated code, and a
substring match is not evidence of parsing. The list below names only what
traces to an actual extraction site, so it understates rather than overstates.

Everything else in these tables is **carried verbatim** — sipnab preserves the
full header, so an unparsed parameter is visible in `get_message`, the TUI
detail pane and any export. Unparsed means "not given a named accessor or a
filter field", not "discarded".

## SIP/SIPS URI parameters (35)

Parameters after a `;` in a SIP URI, e.g. `sip:alice@example.com;transport=tcp`.

<!-- vale off -->

| Parameter | Predefined values | Defined by | sipnab parses |
|---|---|---|---|
| `aai` | No | [RFC 5552](https://www.rfc-editor.org/rfc/rfc5552) | — |
| `bnc` | No | [RFC 6140](https://www.rfc-editor.org/rfc/rfc6140) | — |
| `cause` | Yes | [RFC 4458](https://www.rfc-editor.org/rfc/rfc4458), [RFC 8119](https://www.rfc-editor.org/rfc/rfc8119) | — |
| `ccxml` | No | [RFC 5552](https://www.rfc-editor.org/rfc/rfc5552) | — |
| `comp` | Yes | [RFC 3486](https://www.rfc-editor.org/rfc/rfc3486) | — |
| `content-type` | No | [RFC 4240](https://www.rfc-editor.org/rfc/rfc4240) | — |
| `delay` | No | [RFC 4240](https://www.rfc-editor.org/rfc/rfc4240) | — |
| `duration` | No | [RFC 4240](https://www.rfc-editor.org/rfc/rfc4240) | — |
| `extension` | No | [RFC 4240](https://www.rfc-editor.org/rfc/rfc4240) | — |
| `gr` | No | [RFC 5627](https://www.rfc-editor.org/rfc/rfc5627) | — |
| `iotl` | Yes | [RFC 7549](https://www.rfc-editor.org/rfc/rfc7549) | — |
| `locale` | No | [RFC 4240](https://www.rfc-editor.org/rfc/rfc4240) | — |
| `lr` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `m` | Yes | [RFC 6910](https://www.rfc-editor.org/rfc/rfc6910) | — |
| `maddr` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `maxage` | No | [RFC 5552](https://www.rfc-editor.org/rfc/rfc5552) | — |
| `maxstale` | No | [RFC 5552](https://www.rfc-editor.org/rfc/rfc5552) | — |
| `method` | "get" / "post" | [RFC 5552](https://www.rfc-editor.org/rfc/rfc5552) | — |
| `method` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `ob` | No | [RFC 5626](https://www.rfc-editor.org/rfc/rfc5626) | — |
| `param[n]` | No | [RFC 4240](https://www.rfc-editor.org/rfc/rfc4240) | — |
| `play` | No | [RFC 4240](https://www.rfc-editor.org/rfc/rfc4240) | — |
| `pn-param` | No | [RFC 8599](https://www.rfc-editor.org/rfc/rfc8599) | — |
| `pn-prid` | No | [RFC 8599](https://www.rfc-editor.org/rfc/rfc8599) | — |
| `pn-provider` | No | [RFC 8599](https://www.rfc-editor.org/rfc/rfc8599) | — |
| `pn-purr` | No | [RFC 8599](https://www.rfc-editor.org/rfc/rfc8599) | — |
| `postbody` | No | [RFC 5552](https://www.rfc-editor.org/rfc/rfc5552) | — |
| `repeat` | No | [RFC 4240](https://www.rfc-editor.org/rfc/rfc4240) | — |
| `sg` | No | [RFC 6140](https://www.rfc-editor.org/rfc/rfc6140) | — |
| `sigcomp-id` | No | [RFC 5049](https://www.rfc-editor.org/rfc/rfc5049) | — |
| `target` | No | [RFC 4458](https://www.rfc-editor.org/rfc/rfc4458) | — |
| `transport` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261), [RFC 7118](https://www.rfc-editor.org/rfc/rfc7118) | — |
| `ttl` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `user` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261), [RFC 4967](https://www.rfc-editor.org/rfc/rfc4967) | — |
| `voicexml` | No | [RFC 4240](https://www.rfc-editor.org/rfc/rfc4240) | — |

<!-- vale on -->

## Header field parameters (201)

Parameters attached to a specific header field. The same name can mean
different things on different headers, which is why the header is part of the
registration.

<!-- vale off -->

| Header field | Parameter | Predefined values | Defined by | sipnab parses |
|---|---|---|---|---|
| `Accept` | `q` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Accept-Encoding` | `q` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Accept-Language` | `q` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Alert-Info` | `appearance` | No | [RFC 7463](https://www.rfc-editor.org/rfc/rfc7463) | — |
| `AlertMsg-Error` | `code` | no | [RFC 8876](https://www.rfc-editor.org/rfc/rfc8876) | — |
| `Answer-Mode` | `require` | No | [RFC 5373](https://www.rfc-editor.org/rfc/rfc5373) | — |
| `Authentication-Info` | `cnonce` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authentication-Info` | `nc` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authentication-Info` | `nextnonce` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authentication-Info` | `qop` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authentication-Info` | `rspauth` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authorization` | `algorithm` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261), [RFC 3310](https://www.rfc-editor.org/rfc/rfc3310) | — |
| `Authorization` | `auts` | No | [RFC 3310](https://www.rfc-editor.org/rfc/rfc3310) | — |
| `Authorization` | `cnonce` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authorization` | `nc` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authorization` | `nonce` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authorization` | `opaque` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authorization` | `qop` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authorization` | `realm` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authorization` | `response` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authorization` | `uri` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Authorization` | `username` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Call-Info` | `call-reason` | No | [RFC 9796](https://www.rfc-editor.org/rfc/rfc9796) | — |
| `Call-Info` | `integrity` | No | [RFC 9796](https://www.rfc-editor.org/rfc/rfc9796) | — |
| `Call-Info` | `m` | Yes | [RFC 6910](https://www.rfc-editor.org/rfc/rfc6910) | — |
| `Call-Info` | `purpose` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261), [RFC 5367](https://www.rfc-editor.org/rfc/rfc5367), [RFC 6910](https://www.rfc-editor.org/rfc/rfc6910), [RFC 6993](https://www.rfc-editor.org/rfc/rfc6993), [RFC 7082](https://www.rfc-editor.org/rfc/rfc7082), [RFC 7852](https://www.rfc-editor.org/rfc/rfc7852), [RFC 8688](https://www.rfc-editor.org/rfc/rfc8688), [RFC 9248](https://www.rfc-editor.org/rfc/rfc9248), [RFC 9796](https://www.rfc-editor.org/rfc/rfc9796) | — |
| `Call-Info` | `verified` | Yes | [RFC 9796](https://www.rfc-editor.org/rfc/rfc9796) | — |
| `Contact` | `expires` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | **yes** |
| `Contact` | `mp` | No | [RFC 7044](https://www.rfc-editor.org/rfc/rfc7044) | — |
| `Contact` | `np` | No | [RFC 7044](https://www.rfc-editor.org/rfc/rfc7044) | — |
| `Contact` | `pub-gruu` | No | [RFC 5627](https://www.rfc-editor.org/rfc/rfc5627) | — |
| `Contact` | `q` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Contact` | `rc` | No | [RFC 7044](https://www.rfc-editor.org/rfc/rfc7044) | — |
| `Contact` | `reg-id` | No | [RFC 5626](https://www.rfc-editor.org/rfc/rfc5626) | — |
| `Contact` | `temp-gruu` | No | [RFC 5627](https://www.rfc-editor.org/rfc/rfc5627) | — |
| `Contact` | `temp-gruu-cookie` | No | [RFC 6140](https://www.rfc-editor.org/rfc/rfc6140) | — |
| `Content-Disposition` | `handling` | Yes | [RFC 3204](https://www.rfc-editor.org/rfc/rfc3204), [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261), [RFC 3459](https://www.rfc-editor.org/rfc/rfc3459), [RFC 5621](https://www.rfc-editor.org/rfc/rfc5621) | — |
| `Event` | `adaptive-min-rate` | No | [RFC 6446](https://www.rfc-editor.org/rfc/rfc6446) | — |
| `Event` | `body` | Yes | [RFC 5989](https://www.rfc-editor.org/rfc/rfc5989) | — |
| `Event` | `call-id` | No | [RFC 4235](https://www.rfc-editor.org/rfc/rfc4235) | — |
| `Event` | `effective-by` | No | [RFC 6080](https://www.rfc-editor.org/rfc/rfc6080) | — |
| `Event` | `from-tag` | No | [RFC 4235](https://www.rfc-editor.org/rfc/rfc4235) | — |
| `Event` | `id` | No | [RFC 6665](https://www.rfc-editor.org/rfc/rfc6665) | — |
| `Event` | `include-session-description` | No | [RFC 4235](https://www.rfc-editor.org/rfc/rfc4235) | — |
| `Event` | `max-rate` | No | [RFC 6446](https://www.rfc-editor.org/rfc/rfc6446) | — |
| `Event` | `min-rate` | No | [RFC 6446](https://www.rfc-editor.org/rfc/rfc6446) | — |
| `Event` | `model` | No | [RFC 6080](https://www.rfc-editor.org/rfc/rfc6080) | — |
| `Event` | `profile-type` | Yes | [RFC 6080](https://www.rfc-editor.org/rfc/rfc6080) | — |
| `Event` | `shared` | No | [RFC 7463](https://www.rfc-editor.org/rfc/rfc7463) | — |
| `Event` | `to-tag` | No | [RFC 4235](https://www.rfc-editor.org/rfc/rfc4235) | — |
| `Event` | `vendor` | No | [RFC 6080](https://www.rfc-editor.org/rfc/rfc6080) | — |
| `Event` | `version` | No | [RFC 6080](https://www.rfc-editor.org/rfc/rfc6080) | — |
| `Feature-Caps` | `fcap-name [7]` | No | [RFC 6809](https://www.rfc-editor.org/rfc/rfc6809) | — |
| `From` | `tag` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | **yes** |
| `Geolocation` | `loc-src` | No | [RFC 8787](https://www.rfc-editor.org/rfc/rfc8787) | — |
| `Geolocation-Error` | `code` | Yes | [RFC 6442](https://www.rfc-editor.org/rfc/rfc6442) | — |
| `History-Info` | `mp` | No | [RFC 7044](https://www.rfc-editor.org/rfc/rfc7044) | — |
| `History-Info` | `np` | No | [RFC 7044](https://www.rfc-editor.org/rfc/rfc7044) | — |
| `History-Info` | `rc` | No | [RFC 7044](https://www.rfc-editor.org/rfc/rfc7044) | — |
| `P-Access-Network-Info` | `cgi-3gpp` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `ci-3gpp2` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `ci-3gpp2-femto` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `dsl-location` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `dvb-rcs2-node-id` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `eth-location` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `fiber-location` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `gstn-location` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `i-wlan-node-id` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `local-time-zone` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `operator-specific-GI` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `utran-cell-id-3gpp` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Access-Network-Info` | `utran-sai-3gpp` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Charging-Function-Addresses` | `ccf` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Charging-Function-Addresses` | `ccf-2` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Charging-Function-Addresses` | `ecf` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Charging-Function-Addresses` | `ecf-2` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Charging-Vector` | `icid-generated-at` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Charging-Vector` | `icid-value` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Charging-Vector` | `orig-ioi` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Charging-Vector` | `related-icid` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Charging-Vector` | `related-icid-generated-at` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Charging-Vector` | `term-ioi` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-Charging-Vector` | `transit-ioi` | No | [RFC 7315](https://www.rfc-editor.org/rfc/rfc7315) | — |
| `P-DCS-Billing-Info` | `called` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-Billing-Info` | `calling` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-Billing-Info` | `charge` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-Billing-Info` | `jip` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-Billing-Info` | `locroute` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-Billing-Info` | `rksgroup` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-Billing-Info` | `routing` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-LAES` | `bcid` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-LAES` | `cccid` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-LAES` | `content` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-LAES` | `key (OBSOLETED)` | No | [RFC 3603](https://www.rfc-editor.org/rfc/rfc3603), [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-Redirect` | `count` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-Redirect` | `redirector-uri` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-DCS-Trace-Party-ID` | `timestamp` | No | [RFC 5503](https://www.rfc-editor.org/rfc/rfc5503) | — |
| `P-Refused-URI-List` | `members` | No | [RFC 5318](https://www.rfc-editor.org/rfc/rfc5318) | — |
| `P-Served-User` | `orig-cdiv` | No | [RFC 8498](https://www.rfc-editor.org/rfc/rfc8498) | — |
| `P-Served-User` | `regstate` | Yes | [RFC 5502](https://www.rfc-editor.org/rfc/rfc5502) | — |
| `P-Served-User` | `sescase` | Yes | [RFC 5502](https://www.rfc-editor.org/rfc/rfc5502) | — |
| `Policy-Contact` | `non-cacheable` | Yes | [RFC 6794](https://www.rfc-editor.org/rfc/rfc6794) | — |
| `Priv-Answer-Mode` | `require` | No | [RFC 5373](https://www.rfc-editor.org/rfc/rfc5373) | — |
| `Proxy-Authenticate` | `algorithm` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261), [RFC 3310](https://www.rfc-editor.org/rfc/rfc3310) | — |
| `Proxy-Authenticate` | `authz_server` | No | [RFC 8898](https://www.rfc-editor.org/rfc/rfc8898) | — |
| `Proxy-Authenticate` | `domain` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authenticate` | `error` | No | [RFC 8898](https://www.rfc-editor.org/rfc/rfc8898) | — |
| `Proxy-Authenticate` | `nonce` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authenticate` | `opaque` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authenticate` | `qop` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authenticate` | `realm` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authenticate` | `scope` | No | [RFC 8898](https://www.rfc-editor.org/rfc/rfc8898) | — |
| `Proxy-Authenticate` | `stale` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authorization` | `algorithm` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261), [RFC 3310](https://www.rfc-editor.org/rfc/rfc3310) | — |
| `Proxy-Authorization` | `auts` | No | [RFC 3310](https://www.rfc-editor.org/rfc/rfc3310) | — |
| `Proxy-Authorization` | `cnonce` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authorization` | `nc` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authorization` | `nonce` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authorization` | `opaque` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authorization` | `qop` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authorization` | `realm` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authorization` | `response` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authorization` | `uri` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Proxy-Authorization` | `username` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Reason` | `cause` | Yes | [RFC 3326](https://www.rfc-editor.org/rfc/rfc3326) | — |
| `Reason` | `location` | Yes | [RFC 8606](https://www.rfc-editor.org/rfc/rfc8606) | — |
| `Reason` | `ppi` | No | [RFC 9410](https://www.rfc-editor.org/rfc/rfc9410) | — |
| `Reason` | `text` | No | [RFC 3326](https://www.rfc-editor.org/rfc/rfc3326) | — |
| `Retry-After` | `duration` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Security-Client` | `alg` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Client` | `d-alg` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Client` | `d-qop` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Client` | `d-ver` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Client` | `ealg` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Client` | `mod` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Client` | `port1` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Client` | `port2` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Client` | `prot` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Client` | `q` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Client` | `spi` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Server` | `alg` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Server` | `d-alg` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Server` | `d-qop` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Server` | `d-ver` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Server` | `ealg` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Server` | `mod` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Server` | `port1` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Server` | `port2` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Server` | `prot` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Server` | `q` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Server` | `spi` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Verify` | `alg` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Verify` | `d-alg` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Verify` | `d-qop` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Verify` | `d-ver` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Verify` | `ealg` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Verify` | `mod` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Verify` | `port1` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Verify` | `port2` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Verify` | `prot` | Yes | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Verify` | `q` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Security-Verify` | `spi` | No | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) | — |
| `Session-ID` | `logme` | No (no values are allowed) | [RFC 8497](https://www.rfc-editor.org/rfc/rfc8497) | — |
| `Session-ID` | `remote` | No | [RFC 7989](https://www.rfc-editor.org/rfc/rfc7989) | — |
| `Subscription-State` | `adaptive-min-rate` | No | [RFC 6446](https://www.rfc-editor.org/rfc/rfc6446) | — |
| `Subscription-State` | `expires` | No | [RFC 6665](https://www.rfc-editor.org/rfc/rfc6665) | **yes** |
| `Subscription-State` | `max-rate` | No | [RFC 6446](https://www.rfc-editor.org/rfc/rfc6446) | — |
| `Subscription-State` | `min-rate` | No | [RFC 6446](https://www.rfc-editor.org/rfc/rfc6446) | — |
| `Subscription-State` | `reason` | Yes | [RFC 6665](https://www.rfc-editor.org/rfc/rfc6665) | — |
| `Subscription-State` | `retry-after` | No | [RFC 6665](https://www.rfc-editor.org/rfc/rfc6665) | — |
| `Target-Dialog` | `local-tag` | No | [RFC 4538](https://www.rfc-editor.org/rfc/rfc4538) | — |
| `Target-Dialog` | `remote-tag` | No | [RFC 4538](https://www.rfc-editor.org/rfc/rfc4538) | — |
| `To` | `tag` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | **yes** |
| `Trigger-Consent` | `target-uri` | No | [RFC 5360](https://www.rfc-editor.org/rfc/rfc5360) | — |
| `User-to-User` | `content` | No | [RFC 7433](https://www.rfc-editor.org/rfc/rfc7433) | — |
| `User-to-User` | `encoding` | Yes | [RFC 7433](https://www.rfc-editor.org/rfc/rfc7433) | — |
| `User-to-User` | `purpose` | No | [RFC 7433](https://www.rfc-editor.org/rfc/rfc7433) | — |
| `Via` | `alias` | No | [RFC 5923](https://www.rfc-editor.org/rfc/rfc5923) | — |
| `Via` | `branch` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | **yes** |
| `Via` | `comp` | Yes | [RFC 3486](https://www.rfc-editor.org/rfc/rfc3486) | — |
| `Via` | `keep` | No | [RFC 6223](https://www.rfc-editor.org/rfc/rfc6223) | — |
| `Via` | `maddr` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `Via` | `oc` | Yes | [RFC 7339](https://www.rfc-editor.org/rfc/rfc7339) | — |
| `Via` | `oc-algo` | Yes | [RFC 7339](https://www.rfc-editor.org/rfc/rfc7339), [RFC 7415](https://www.rfc-editor.org/rfc/rfc7415) | — |
| `Via` | `oc-seq` | Yes | [RFC 7339](https://www.rfc-editor.org/rfc/rfc7339) | — |
| `Via` | `oc-validity` | Yes | [RFC 7339](https://www.rfc-editor.org/rfc/rfc7339) | — |
| `Via` | `received` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261), [RFC 7118](https://www.rfc-editor.org/rfc/rfc7118) | — |
| `Via` | `received-realm` | No | [RFC 8055](https://www.rfc-editor.org/rfc/rfc8055) | — |
| `Via` | `rport` | No | [RFC 3581](https://www.rfc-editor.org/rfc/rfc3581) | — |
| `Via` | `sigcomp-id` | No | [RFC 5049](https://www.rfc-editor.org/rfc/rfc5049) | — |
| `Via` | `ttl` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `WWW-Authenticate` | `algorithm` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261), [RFC 3310](https://www.rfc-editor.org/rfc/rfc3310) | — |
| `WWW-Authenticate` | `authz_server` | No | [RFC 8898](https://www.rfc-editor.org/rfc/rfc8898) | — |
| `WWW-Authenticate` | `domain` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `WWW-Authenticate` | `error` | No | [RFC 8898](https://www.rfc-editor.org/rfc/rfc8898) | — |
| `WWW-Authenticate` | `nonce` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `WWW-Authenticate` | `opaque` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `WWW-Authenticate` | `qop` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `WWW-Authenticate` | `realm` | No | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |
| `WWW-Authenticate` | `scope` | No | [RFC 8898](https://www.rfc-editor.org/rfc/rfc8898) | — |
| `WWW-Authenticate` | `stale` | Yes | [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) | — |

<!-- vale on -->

## Option tags (36)

Values for `Require`, `Supported`, `Proxy-Require` and `Unsupported`. They
negotiate extensions, so a `420 Bad Extension` is usually an option tag one end
required and the other did not support — compare the two lists.

<!-- vale off -->

| Option tag | Defined by |
|---|---|
| `100rel` | [RFC 3262](https://www.rfc-editor.org/rfc/rfc3262) |
| `199` | [RFC 6228](https://www.rfc-editor.org/rfc/rfc6228) |
| `answermode` | [RFC 5373](https://www.rfc-editor.org/rfc/rfc5373) |
| `early-session` | [RFC 3959](https://www.rfc-editor.org/rfc/rfc3959) |
| `eventlist` | [RFC 4662](https://www.rfc-editor.org/rfc/rfc4662) |
| `explicitsub` | [RFC 7614](https://www.rfc-editor.org/rfc/rfc7614) |
| `from-change` | [RFC 4916](https://www.rfc-editor.org/rfc/rfc4916) |
| `geolocation-http` | [RFC 6442](https://www.rfc-editor.org/rfc/rfc6442) |
| `geolocation-sip` | [RFC 6442](https://www.rfc-editor.org/rfc/rfc6442) |
| `gin` | [RFC 6140](https://www.rfc-editor.org/rfc/rfc6140) |
| `gruu` | [RFC 5627](https://www.rfc-editor.org/rfc/rfc5627) |
| `histinfo` | [RFC 7044](https://www.rfc-editor.org/rfc/rfc7044) |
| `ice` | [RFC 5768](https://www.rfc-editor.org/rfc/rfc5768) |
| `join` | [RFC 3911](https://www.rfc-editor.org/rfc/rfc3911) |
| `multiple-refer` | [RFC 5368](https://www.rfc-editor.org/rfc/rfc5368) |
| `norefersub` | [RFC 4488](https://www.rfc-editor.org/rfc/rfc4488) |
| `nosub` | [RFC 7614](https://www.rfc-editor.org/rfc/rfc7614) |
| `outbound` | [RFC 5626](https://www.rfc-editor.org/rfc/rfc5626) |
| `path` | [RFC 3327](https://www.rfc-editor.org/rfc/rfc3327) |
| `policy` | [RFC 6794](https://www.rfc-editor.org/rfc/rfc6794) |
| `precondition` | [RFC 3312](https://www.rfc-editor.org/rfc/rfc3312) |
| `pref` | [RFC 3840](https://www.rfc-editor.org/rfc/rfc3840) |
| `privacy` | [RFC 3323](https://www.rfc-editor.org/rfc/rfc3323) |
| `recipient-list-invite` | [RFC 5366](https://www.rfc-editor.org/rfc/rfc5366) |
| `recipient-list-message` | [RFC 5365](https://www.rfc-editor.org/rfc/rfc5365) |
| `recipient-list-subscribe` | [RFC 5367](https://www.rfc-editor.org/rfc/rfc5367) |
| `record-aware` | [RFC 7866](https://www.rfc-editor.org/rfc/rfc7866) |
| `replaces` | [RFC 3891](https://www.rfc-editor.org/rfc/rfc3891) |
| `resource-priority` | [RFC 4412](https://www.rfc-editor.org/rfc/rfc4412) |
| `sdp-anat` | [RFC 4092](https://www.rfc-editor.org/rfc/rfc4092) |
| `sec-agree` | [RFC 3329](https://www.rfc-editor.org/rfc/rfc3329) |
| `siprec` | [RFC 7866](https://www.rfc-editor.org/rfc/rfc7866) |
| `tdialog` | [RFC 4538](https://www.rfc-editor.org/rfc/rfc4538) |
| `timer` | [RFC 4028](https://www.rfc-editor.org/rfc/rfc4028) |
| `trickle-ice` | [RFC 8840](https://www.rfc-editor.org/rfc/rfc8840) |
| `uui` | [RFC 7433](https://www.rfc-editor.org/rfc/rfc7433) |

<!-- vale on -->

