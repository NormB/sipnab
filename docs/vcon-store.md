# Send sipnab's vCons to vcon.store

vcon.store is a hosted store for
[vCons](glossary.md#vcon). This page sends the containers sipnab writes to it
with `sipnab --vcon-forward`, the forwarder that
[Deliver the spool to a store](vcon.md#deliver-the-spool-to-a-store)
describes.

**Status on 2026-10-07: sipnab's containers work only through a compat
mode, and only when they carry audio.** vcon.store refuses `extensions` in the
form both vCon drafts define, so a sipnab container sent unchanged draws `400`.
`--vcon-forward-kind vcon-store` sends a copy the store accepts, and leaves
the container on disk unchanged. Even with it, the store refuses a container
whose Dialog Object has no `parties`, which is what sipnab writes for a call
whose container carries no audio: the run kept none, or `--redact` withheld it.
sipnab also writes one for a call whose audio it cannot attribute to a party,
such as audio that a media relay sent. [The measurements](#the-measurements) are the evidence.

## Before you send anything

A capture carries personal data: telephone numbers, addresses, the headers
your platform sets, and, with `--retain-audio`, the call audio. vcon.store is
another party's system. Decide what may leave the machine first:

- `--redact` replaces identities, addresses and correlation identifiers with
  keyed tokens, and withholds the audio. It works on a capture file (`-I`),
  not on a live capture.
- A redacted container carries no audio, so its Dialog Object has no
  `parties`, and vcon.store refuses it. The compat mode refuses it before sending, with
  that reason. Today the only sipnab container vcon.store accepts is one
  exported without `--redact` and with audio that sipnab attributed to the
  parties: the call audio and the identifiers the signaling carried, as
  captured.
- [What may you conclude](vcon.md#someone-handed-you-a-sipnab-vcon-what-may-you-conclude)
  lists what a container carries.

## 1. Write the containers

Export the calls from a capture file with their audio. `--retain-audio` makes
sipnab type each call's Dialog Object `recording`. The object names the
parties, which the store requires, when each audio channel came from the media
address and port that one party advertised in its own SDP. Audio from any
other address, such as a media relay's, gets no `parties`, and the store
refuses that container. This container is not redacted: it carries the audio
and the identifiers as captured.

```sh
sipnab -N --no-cli-print -I calls.pcap --retain-audio \
  --export-vcon-when "state == 'Completed'" --export-vcon-dir spool
```

With `--redact` added, the same command writes containers without audio, and
step 3 moves each one to `spool/failed` with the reason.

sipnab prints `Wrote N vCon container(s) to 'spool'.`

## 2. Put the token in a file

vcon.store authenticates with a bearer token. Put the token alone in a file
only you can read. The `vcon-store` kind sends it as
`Authorization: Bearer <token>`. The forwarder refuses a file that other users
can read:

```sh
# Run all of these, in order.
umask 077
printf '%s\n' "$VCON_STORE_TOKEN" > vcon-store.key
```

`$VCON_STORE_TOKEN` is the token vcon.store issued you. The forwarder never
prints it, and removes it from any answer it keeps. Instead of a file, the
`SIPNAB_VCON_FORWARD_AUTH` environment variable can hold the token.

## 3. Send them

```sh
# Run all of these, in order.
STORE_URL=https://api.vcon.store
sipnab --vcon-forward spool --vcon-forward-kind vcon-store \
  --vcon-forward-url "$STORE_URL" --vcon-forward-auth-file vcon-store.key \
  --vcon-forward-once
echo "exit $?"
```

`--vcon-forward-kind vcon-store` adds `/v1/vcons` to the base URL, forms the
header from the token, and applies the compat mode below. The same settings
can live in `sipnab.toml`:

```toml
[vcon_forward]
kind = "vcon-store"
url = "https://api.vcon.store"
auth_file = "/etc/sipnab/vcon-store.key"
```

For each container the forwarder logs one line naming the change it made to
the copy it sent, then a `delivered` line with the store's status, and moves
the file to `spool/delivered`. The exit status is `0` when the store accepted
every container. A container the store or the compat mode refused is in
`spool/failed`, beside a `.error.json` record that says why. A `401` or `403`
is different: it refuses the token or the client for every container, so the
forwarder stops, moves nothing, logs the status and the start of the answer,
and exits `3`.

sipnab's tests run the `vcon-store` kind against a stand-in that answers as the
maintainer measured vcon.store answering ([`tests/vcon_forward_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/vcon_forward_test.rs)), not
against vcon.store itself.

## What the compat mode changes, and why

The `vcon-store` kind changes the copy the forwarder SENDS, as
`--vcon-forward-compat vcon-store` does: the flag is the same adaptation for
any kind, and `--vcon-forward-compat none` turns it off for this one. The
file in the spool, and the copy in `spool/delivered`, keep the form the drafts
define. The forwarder logs each change, one line per container.

| In the container | Sent to vcon.store | Why |
|---|---|---|
| `"extensions": ["sip-signaling", "CC"]` | `"extensions": {"sip-signaling": true, "CC": true}` | Section 4.1.3 of [draft-ietf-vcon-vcon-core-02](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-02#section-4.1.3), and of every revision since through [-04](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.1.3), defines `extensions` as an array of strings. vcon.store refuses that and accepts an object. The copy keeps every name, in its order. |
| a Dialog Object with no `type` or no `parties` | nothing: the container is not sent | vcon.store requires both on every Dialog Object, as draft-ietf-vcon-vcon-core-02 did. sipnab writes a Dialog Object without `parties` when the container carries no audio: the `recording` placeholder of [section 4.3 of draft-ietf-vcon-vcon-core-04](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3), on which [section 4.3.4](https://datatracker.ietf.org/doc/html/draft-ietf-vcon-vcon-core-04#section-4.3.4) makes `parties` a SHOULD. A container sipnab wrote before it followed -04 lacks `type` there as well. sipnab also writes a `recording` with audio and no `parties` when an audio channel came from an address no party advertised in its SDP, such as a media relay's. The forwarder does not invent what sipnab did not observe, and does not drop the object, which would leave other indexes pointing at nothing. It moves the container to `spool/failed` with a reason. For a container with no audio, the reason names `--retain-audio` and `--redact`. For audio sipnab could not attribute, it says so, and that exporting again gives the same container. |

The forwarder sends every other byte of the container as sipnab wrote it. You can
drop the mode once vcon.store accepts `extensions` as the array of strings the drafts
define.

## The measurements

The maintainer measured these against vcon.store's API on 2026-10-07. This
page's commands did not contact the store.

| Sent | vcon.store answered |
|---|---|
| `POST /v1/vcons` with `"extensions": ["sip-signaling", "CC"]` | `400`, `extensions: Expected object, received array` |
| the same with `extensions` as an object of names mapped to `true` | `201`, stored as sent |
| a vCon with no audio, whose Dialog Object is `{}` | `400`: the store requires `type` and `parties` |
| the same with `extensions` removed | `201` |
| `GET` of a stored vCon | the content unchanged, inside a `_meta` envelope |
| `DELETE` of a stored vCon | `200`, and a `GET` after it `404` |
| a request with Python's default HTTP `User-Agent` | `403`, `error code: 1010`, from the Cloudflare front. The front accepted a curl `User-Agent`. The forwarder sends `User-Agent: sipnab/<version>` |
| on 2026-10-09, sipnab's container with audio, sent by `--vcon-forward-kind vcon-store` | `201`; a `GET` returned it unchanged apart from the compat mode's `extensions` object |
| on 2026-10-09, the `recording` Dialog Object sipnab writes for a call without audio (no `parties`, no content), with `extensions` as an object | `400`, `dialog.0.parties: expected array, received undefined` |

Not measured: whether vcon.store answers `409` for a uuid it already holds, or
accepts a `PUT` to `/v1/vcons/{uuid}`. `--vcon-forward-replace-url` exists for a
store that does, and this page does not use it. The store refuses a `recording` Dialog Object with no
`body`, which is what step 1 writes under `--redact`, for its missing
`parties`, as the last row shows.

## What the store adds, and what it does not mean

On each create the store wrote one entry to its transparency log (SCITT): the
event `vcon_created`, a SHA-256 hash of the payload, a COSE signed statement
and a receipt. Each stored vCon also comes back with a `_meta` envelope that
says `form: unsigned`, `consentStatus: unknown` and `retentionAction: redact`.

- **The signature is the store's, not sipnab's.** It says what vcon.store
  received. The container it covers is an observation from a tap, which
  sipnab never signs, so the signature does not make the container a
  recording.
- **`consentStatus: unknown` is accurate.** sipnab records no consent, and a
  container carries none.

## Read a stored vCon back

`sipnab --vcon-fetch` reads a container back by its uuid, with the same key
file. The `vcon-store` kind reads `/v1/vcons/{uuid}`, sends the key as
`Authorization: Bearer <key>`, and removes the `_meta` member the store adds,
so the file holds the container alone:

```sh
sipnab --vcon-fetch 018bcfe5-6800-8a6b-a667-78f1c5213800 --vcon-fetch-kind vcon-store --vcon-fetch-url https://api.vcon.store --vcon-fetch-auth-file vcon-store.key --vcon-fetch-out fetched
```

The container is the copy the store accepted, so its `extensions` is the
object the compat mode sent, not the array the drafts define. The fetcher
writes it and reports the schema finding, and the run exits `1`. Measured on
2026-10-09: a container sipnab exported from
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap), sent with `--vcon-forward-kind
vcon-store` (`201`), read back (`200`, with `_meta`), then deleted (`200`).
A read after the delete answered `404`, and a read with a wrong key `401`. More:
[Fetch a stored vCon](vcon.md#fetch-a-stored-vcon).

## When something does not work

- **Every container lands in `spool/failed` with status `400` and
  `extensions: Expected object, received array`.** Use
  `--vcon-forward-kind vcon-store` (or `--vcon-forward-compat vcon-store`, and
  no `--vcon-forward-compat none`), move the files from `spool/failed` back
  to `spool`, and run the forwarder again.
- **A container lands in `spool/failed` with a reason about `type` and
  `parties`.** The container carries no audio: the run kept none for that
  call, or the export ran with `--redact`. Export it again with
  `--retain-audio` and without `--redact`.
- **A container lands in `spool/failed` with a reason that says it carries
  audio sipnab could not attribute to a party.** An audio channel came from
  an address and port that no party advertised in its own SDP, such as a media
  relay's. Exporting the same capture again gives the same container. vcon.store
  does not accept it.
- **The forwarder exits `3` and logs `403` with `error code: 1010`.** The
  Cloudflare front refused the request's client. The forwarder sends
  `User-Agent: sipnab/<version>`. Check that nothing between it and the store
  replaces that header. It moved no file, so run it again once you fix that.
- **The forwarder exits `3` and logs `401`.** The token in `vcon-store.key` is
  wrong or expired. Every container is still in `spool`.
