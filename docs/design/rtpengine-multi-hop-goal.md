# rtpengine: the multi-hop goal

This page records the goal that relay attribution serves. It does not describe
what sipnab does today. For the current behavior, see
[Attribute media on an rtpengine relay](../rtpengine.md).

- What docs/rtpengine.md documents is one hop naming its own media.
- The proof ran against a recorded capture and against a live relay.
- This page states what that foundation exists for. So the next phase aims
  at a goal rather than at whatever comes next.

The goal is a call that crosses an SBC, a proxy, an rtpengine and a PBX,
assembled end to end.

- Then an operator can ask a question in their own words.
- An agent answers with evidence from every hop the call touched.

Naming media on the relay is the hop that was missing. It is the only hop that
carries no SIP of its own. Once each hop can name a call, an agent can:

- filter to a customer, by caller, callee, trunk, address, or time window,
- pull the whole call rather than one machine's view of it.

These are the questions that arrive, and what answering each one takes.

| The customer says | The question really is | What the answer needs |
|---|---|---|
| "Our calls sound bad" | Where in the path did the media degrade? | Per-hop loss, jitter and MOS on the SAME call, so a good leg and a bad leg separate cleanly |
| "Calls are not completing" | Which hop rejected it, and what did it say? | The final response and its origin hop, plus whether media was ever negotiated |
| "Calls drop after a while" | Who tore it down, and on what clock? | The BYE or the timeout, and which side sent it |
| "We hear them, they can't hear us" | Which direction is missing, and from where? | Both directions of media at each hop, not just a packet count |
| "It only fails for one carrier" | What is different about that path? | The same call shape across two trunks, compared |

## "Our calls sound bad"

The hard part is not measuring quality. It is locating it.

- A relay reporting 2% loss tells you nothing on its own.
- The question is whether the loss was already there when the media arrived,
  or appeared on the way out.

That needs the same call measured on both sides of each hop. That needs each
hop to agree on the call's name. On the relay, relay attribution supplies
that agreement.

The analysis then reads as a chain:

- clean into the SBC,
- clean into the relay,
- lossy out of the relay.

Now the fault has an address rather than a symptom.

Watch for the answer being "neither hop":

- Identical loss at every hop points at the access network.
- A codec that changes between hops points at transcoding rather than at the
  network.

## "Calls are not completing"

Same filter, different evidence. Here the media is usually absent rather than
degraded. So the question moves to signaling, and to the gap between them.

The failure modes separate cleanly once you can see every hop at once:

- **A final response from an upstream hop**, which names the rejecter. The
  response class matters, and the classes lead to different owners:
  - A 4xx is the far end declining.
  - A 5xx is a server failing.
  - A 6xx is a global refusal.
- **No response at all**, which is a timeout. The hop that stopped answering
  is the one to look at.
- **A call answered with no media**, which is a negotiation failure rather
  than a routing one. The signaling succeeded and the SDP did not.
- **A relay with no ports left**. This looks like a random failure from the
  proxy's side. It is obvious from the relay's.

The last two are exactly the cases a signaling-only view gets wrong. From the
proxy, the call looks answered.

## "Calls drop after a while"

A drop has a clock attached, and the clock identifies the cause.

- A tear-down at a round number is a timer: a session timer, a NAT binding, a
  relay's own media timeout.
- A tear-down when media stopped is the media stopping.
- Reading the relay's teardown against the proxy's BYE says which came first.
  That is the whole question.

## "We hear them, they can't hear us"

One-way audio is a direction problem. A relay is where directions become
visible.

- It holds both parties' sockets.
- So a leg with media arriving and nothing leaving is plainly asymmetric.

The value of naming the call is being able to say WHICH call is asymmetric on
a box carrying hundreds.

## "It only fails for one carrier"

The comparison case.

- Two calls of the same shape go down two trunks.
- Their assembly is the same.
- They differ in one hop's behavior.

This is hard to do by hand across machines. It is straightforward once every
hop names its calls the same way.
