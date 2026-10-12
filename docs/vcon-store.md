# Send sipnab's vCons to vcon.store

vcon.store is a hosted store for
[vCons](glossary.md#vcon). This page sends the containers sipnab writes to it
with `sipnab --vcon-forward`, the forwarder that
[Deliver the spool to a store](vcon.md#deliver-the-spool-to-a-store)
describes.

**Status on 2026-10-11: vcon.store accepts the two forms it refused on
2026-10-07**: `extensions` as the array of strings both vCon drafts define, and
the `recording` Dialog Object without `parties` that sipnab writes for a call
whose container carries no audio. It answers `409` for a uuid it already holds,
and `PUT /v1/vcons/{uuid}` replaces the held copy. The forwarder sends each container byte for
byte. Not measured: a `recording` that carries audio but no
`parties`, which sipnab writes when an audio channel came from an address no
party advertised in its SDP, such as a media relay's.
[The measurements](#the-measurements) are the evidence.

## Before you send anything

A capture carries personal data: telephone numbers, addresses, the headers
your platform sets, and, with `--retain-audio`, the call audio. vcon.store is
another party's system. Decide what may leave the machine first:

- `--redact` replaces identities, addresses and correlation identifiers with
  keyed tokens, and withholds the audio. It works on a capture file (`-I`),
  not on a live capture.
- A redacted container carries no audio, so its `recording` Dialog Object has
  no `parties` and no content. vcon.store accepted that form when measured on
  2026-10-09.
- A container exported without `--redact` and with `--retain-audio` carries
  the call audio and the identifiers the signaling carried, as captured.
- [What may you conclude](vcon.md#someone-handed-you-a-sipnab-vcon-what-may-you-conclude)
  lists what a container carries.

## 1. Write the containers

Export the calls from a capture file with their audio. `--retain-audio` makes
sipnab put each call's audio in its `recording` Dialog Object. The object names
the parties when each audio channel came from the media address and port that
one party advertised in its own SDP, and has no `parties` otherwise. This
container is not redacted: it carries the audio and the identifiers as
captured.

```sh
sipnab -N --no-cli-print -I calls.pcap --retain-audio \
  --export-vcon-when "state == 'Completed'" --export-vcon-dir spool
```

With `--redact` added, and `--retain-audio` removed, the same command writes
redacted containers without audio.

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

`--vcon-forward-kind vcon-store` adds `/v1/vcons` to the base URL and forms
the header from the token. It does not change the container. The same
settings can live in `sipnab.toml`:

```toml
[vcon_forward]
kind = "vcon-store"
url = "https://api.vcon.store"
auth_file = "/etc/sipnab/vcon-store.key"
```

For each container the forwarder logs a `delivered` line with the store's
status, and moves the file to `spool/delivered`. The exit status is `0` when
the store accepted every container. A container the store refused is in
`spool/failed`, beside a `.error.json` record that says why.
`sipnab --vcon-spool-status spool` prints the pending, delivered and failed
counts and the store's answer from each `.error.json` record, read from the
files without sending anything. A capture run with `--mcp` or `--api` answers
the same through the MCP tool
[`vcon_spool_status`](mcp-tools.md#vcon_spool_status) and
[`GET /v1/vcon/spool`](rest-api.md#get-v1vconspool). A `401` or `403`
is different: it refuses the token or the client for every container, so the
forwarder stops, moves nothing, logs the status and the start of the answer,
and exits `3`.

sipnab's tests run the `vcon-store` kind against a stand-in that answers as the
maintainer measured vcon.store answering on 2026-10-11, and against one that
answers as it did on 2026-10-07
([`tests/vcon_forward_test.rs`](https://github.com/NormB/sipnab/blob/main/tests/vcon_forward_test.rs)), not
against vcon.store itself.

## The measurements

The maintainer measured these against vcon.store's API. This page's commands
did not contact the store.

On 2026-10-09, with the sipnab 0.5.209 release binary and a container
exported from
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap):

| Sent | vcon.store answered |
|---|---|
| `POST /v1/vcons`, the container with audio, `"extensions": ["sip-signaling", "CC"]`, sent unchanged | `201`; a `GET` returned `extensions` as the same array |
| the `recording` Dialog Object sipnab writes for a call without audio (no `parties`, no content) | `201`, stored as sent |
| a `POST` of a uuid the store already held | `500`, a problem document of type `https://vcon.store/errors/internal-error`, `An unexpected error occurred`, twice. Changed by 2026-10-11; see below |
| a `GET` with Python's default HTTP `User-Agent`, with Go's, with none, and with `sipnab/0.5.209` | `200` for each |
| a `GET` of a stored vCon | the content, with a top-level `_meta` member added |
| `DELETE /v1/vcons/{uuid}` | `200`, `{"deleted":true,...}`; a `GET` after it `404`, `{"error":"vCon not found"}` |

On 2026-10-11, with a container exported from the same capture, sent with curl:

| Sent | vcon.store answered |
|---|---|
| `POST /v1/vcons`, a new uuid | `201`, `{"uuid":...,"stored_at":...}` |
| a second `POST` of the same uuid | `409`, `{"error":"vCon already exists","details":[{"path":["uuid"],"message":"a vCon with uuid ... already exists; use PUT to replace it"}]}` |
| `PUT /v1/vcons/{uuid}` with a changed `subject`, same uuid | `200`; a `GET` returned the changed `subject` |
| the `recording` Dialog Object without `parties` and content | `201` |
| `DELETE /v1/vcons/{uuid}` | `200`; a `GET` after it `404` |

On 2026-10-07, kept as history:

| Sent | vcon.store answered |
|---|---|
| `POST /v1/vcons` with `"extensions": ["sip-signaling", "CC"]` | `400`, `extensions: Expected object, received array` |
| the same with `extensions` as an object of names mapped to `true` | `201`, stored as sent |
| a vCon with no audio, whose Dialog Object is `{}` | `400`: the store required `type` and `parties` |
| the same with `extensions` removed | `201` |
| a request with Python's default HTTP `User-Agent` | `403`, `error code: 1010`, from the Cloudflare front. The front accepted a curl `User-Agent` |

A `409` for a held uuid is a refusal: the container goes to `spool/failed`
with the store's answer in its `.error.json` record, and
`--vcon-forward-once` exits `1`. To replace the held copy instead, name the
`PUT` endpoint with `--vcon-forward-replace-url`. The forwarder then sends the
container there after the `409`:

```sh
sipnab --vcon-forward spool --vcon-forward-kind vcon-store --vcon-forward-url https://api.vcon.store --vcon-forward-auth-file vcon-store.key --vcon-forward-replace-url 'https://api.vcon.store/v1/vcons/{uuid}'
```

Replacing is off by default: it overwrites what the store holds, which is the
operator's decision. The forwarder retries a `500` after a back-off, as it
retries every `5xx`.

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

The container is the copy the store accepted, as sipnab sent it. Measured on
2026-10-09: a container sipnab exported from
[`tests/pcap-samples/sip-rtp-g711.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-rtp-g711.pcap), sent with `--vcon-forward-kind
vcon-store` (`201`), read back with `--vcon-fetch` (the file held `extensions`
as the array and no `_meta`), then deleted (`200`). A read after the delete
answered `404`. More:
[Fetch a stored vCon](vcon.md#fetch-a-stored-vcon).

## When something does not work

- **Every container lands in `spool/failed` with status `400` and
  `extensions: Expected object, received array`.** The store refuses the form
  the drafts define, as vcon.store did on 2026-10-07. sipnab no longer changes
  the copy it sends, so such a store does not accept sipnab's containers.
- **A container lands in `spool/failed` with status `409` and `vCon already
  exists`.** The store already holds that uuid (`--vcon-fetch` reads it
  back). To replace the held copy, move the file back into `spool` and run
  the forwarder with
  `--vcon-forward-replace-url 'https://api.vcon.store/v1/vcons/{uuid}'`.
- **A container stays in `spool`, and the log says `answered 500; will
  retry`.** The store is in trouble; the forwarder tries again after its
  back-off.
- **The forwarder exits `3` and logs `403` with `error code: 1010`.** The
  Cloudflare front refused the request's client, as it refused Python's
  default `User-Agent` on 2026-10-07. The forwarder sends
  `User-Agent: sipnab/<version>`. Check that nothing between it and the store
  replaces that header. It moved no file, so run it again once you fix that.
- **The forwarder exits `3` and logs `401`.** The token in `vcon-store.key` is
  wrong or expired. Every container is still in `spool`.
