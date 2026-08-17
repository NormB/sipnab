# SIP request methods

Every method in the IANA registry, the RFC section that defines it, and which
dialog state machine sipnab runs it through.

**Source.** <https://www.iana.org/assignments/sip-parameters/sip-parameters-6.csv>
— the IANA *Methods* registry, retrieved 2026-07-30. [RFC 3261](https://www.rfc-editor.org/rfc/rfc3261) defines six of
these and later RFCs register the rest, the same arrangement as the response
codes in [SIP response codes](sip-response-codes.md).

`SipMethod` in [`src/sip/method.rs`](../src/sip/method.rs) names all fourteen,
and `covers_the_iana_methods_registry` holds it to this list. A method outside
the registry parses as `Custom` and takes the generic dialog handler, which is
right for a private extension and wrong for a registered one nobody noticed.

## Dialog state machines

sipnab dispatches on the method that opened the dialog, corrected for the four
methods that cannot open one. `ACK`, `BYE`, `CANCEL` and `PRACK` each
presuppose an INVITE ([RFC 3261 §13.2.2.4](https://www.rfc-editor.org/rfc/rfc3261#section-13.2.2.4),
[§15.1](https://www.rfc-editor.org/rfc/rfc3261#section-15.1),
[§9.1](https://www.rfc-editor.org/rfc/rfc3261#section-9.1),
[RFC 3262 §4](https://www.rfc-editor.org/rfc/rfc3262#section-4)), so a capture
that opens on one is an INVITE dialog seen from its middle and runs through the
INVITE machine. Two more methods get their own machine and the rest share a
generic one.

Which machine handles a message is one question. Which *transaction* the
message belongs to is another. A response answers the transaction its `CSeq`
method names ([RFC 3261 §8.1.1.5](https://www.rfc-editor.org/rfc/rfc3261#section-8.1.1.5)).
So a `200 OK` in an INVITE dialog means the callee picked up only when that
`CSeq` says `INVITE`. The same code answering a `CANCEL` means the cancellation
arrived, and nothing more.

| Machine | Methods | Terminal states |
|---|---|---|
| INVITE | `INVITE`, `ACK`, `BYE`, `CANCEL`, `PRACK` | `InCall`, `Completed`, `Canceled`, `Failed` |
| REGISTER | `REGISTER` | `Registered`, `Failed` |
| SUBSCRIBE | `SUBSCRIBE` | `Active`, `Terminated` |
| generic | the other seven | `Completed`, `Failed` |

<!-- vale off -->

<!-- The Description column quotes the RFC that defines each method. Normative
     text is not ours to reword for a house style guide. -->

| Method | Machine | Defined in | Description |
|---|---|---|---|
| `ACK` | INVITE | [RFC 3261 §17.1.1.3](https://www.rfc-editor.org/rfc/rfc3261#section-17.1.1.3) | This section specifies the construction of ACK requests sent within the client transaction. A UAC core that generates an ACK for 2xx MUST instead follow the rules described in Section 13. |
| `BYE` | INVITE | [RFC 3261 §15.1](https://www.rfc-editor.org/rfc/rfc3261#section-15.1) | A BYE request is constructed as would any other request within a dialog, as described in Section 12. Once the BYE is constructed, the UAC core creates a new non-INVITE client transaction, and passes it the BYE request. |
| `CANCEL` | INVITE | [RFC 3261 §9](https://www.rfc-editor.org/rfc/rfc3261#section-9) | The previous section has discussed general UA behavior for generating requests and processing responses for requests of all methods. In this section, we discuss a general purpose method, called CANCEL. |
| `INFO` | generic | [RFC 6086 §4](https://www.rfc-editor.org/rfc/rfc6086#section-4) | The INFO method provides a mechanism for transporting application level information that can further enhance a SIP application. Section 8 gives more details on the types of applications for which the use of INFO is appropriate. |
| `INVITE` | INVITE | [RFC 3261 §13](https://www.rfc-editor.org/rfc/rfc3261#section-13) | When a user agent client desires to initiate a session (for example, audio, video, or a game), it formulates an INVITE request. The INVITE request asks a server to establish a session. |
| `MESSAGE` | generic | [RFC 3428 §3](https://www.rfc-editor.org/rfc/rfc3428#section-3) | When one user wishes to send an instant message to another, the sender formulates and issues a SIP request using the new MESSAGE method defined by this document. |
| `NOTIFY` | generic | [RFC 6665 §3.2](https://www.rfc-editor.org/rfc/rfc6665#section-3.2) | NOTIFY requests are sent to inform subscribers of changes in state to which the subscriber has a subscription. Subscriptions are created using the SUBSCRIBE method. |
| `OPTIONS` | generic | [RFC 3261 §11](https://www.rfc-editor.org/rfc/rfc3261#section-11) | The SIP method OPTIONS allows a UA to query another UA or a proxy server as to its capabilities. This allows a client to discover information about the supported methods, content types, extensions, codecs, etc. |
| `PRACK` | INVITE | [RFC 3262 §6](https://www.rfc-editor.org/rfc/rfc3262#section-6) | This specification defines a new SIP method, PRACK. The semantics of this method are described above. |
| `PUBLISH` | generic | [RFC 3903 §3](https://www.rfc-editor.org/rfc/rfc3903#section-3) | This document defines a new SIP method, PUBLISH, for publishing event state. PUBLISH is similar to REGISTER in that it allows a user to create, modify, and remove state in another entity which manages this state on behalf of the user. |
| `REFER` | generic | [RFC 3515 §2](https://www.rfc-editor.org/rfc/rfc3515#section-2) | REFER is a SIP method as defined by RFC 3261 [1]. The REFER method indicates that the recipient (identified by the Request-URI) should contact a third party using the contact information provided in the request. |
| `REGISTER` | REGISTER | [RFC 3261 §10](https://www.rfc-editor.org/rfc/rfc3261#section-10) | SIP offers a discovery capability. If a user wants to initiate a session with another user, SIP must discover the current host(s) at which the destination user is reachable. |
| `SUBSCRIBE` | SUBSCRIBE | [RFC 6665 §3.1](https://www.rfc-editor.org/rfc/rfc6665#section-3.1) | The SUBSCRIBE method is used to request current state and state updates from a remote node. SUBSCRIBE requests are target refresh requests, as that term is defined in [RFC3261]. |
| `UPDATE` | generic | [RFC 3311 §3](https://www.rfc-editor.org/rfc/rfc3311#section-3) | Operation of this extension is straightforward. The caller begins with an INVITE transaction, which proceeds normally. |

<!-- vale on -->

Registry references beyond the defining RFC, where a later document updates the
method: `INVITE` [RFC3261][RFC6026].
