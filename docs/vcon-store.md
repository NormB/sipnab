# Send sipnab's vCons to vcon.store

vcon.store is a hosted store for
[vCons](glossary.md#vcon). This page sends the containers sipnab writes to it.
It uses `sipnab --vcon-forward`, the forwarder that
[Deliver the spool to a store](vcon.md#deliver-the-spool-to-a-store)
describes.

The forwarder sends each container byte for byte: it does not change what
sipnab wrote.

## Before you send anything

A capture carries personal data:

- telephone numbers,
- addresses,
- the headers your platform sets,
- with `--retain-audio`, the call audio.

vcon.store is another party's system. Decide what may leave the machine first:

- `--redact` replaces identities, addresses and correlation identifiers with
  keyed tokens. It also withholds the audio.
  - It works on a capture file (`-I`), not on a live capture.
- A redacted container carries no audio. Its `recording` Dialog Object names
  the parties and has no `body`.
- A container exported without `--redact` and with `--retain-audio` carries
  the call audio and the identifiers the signaling carried, as captured.
- [What may you conclude](vcon.md#someone-handed-you-a-sipnab-vcon-what-may-you-conclude)
  lists what a container carries.

## Write the containers

Export the calls from a capture file with their audio.

- `--retain-audio` keeps each call's audio whole, from the first frame.
- It makes sipnab put the audio in its `recording` Dialog Object.
- The object names the parties when each audio channel came from the media
  address and port that one party advertised in its own SDP.
  - Otherwise the object has no `parties`. That is the usual case when a media
    relay carries the audio.
- This container is not redacted. It carries the audio and the identifiers as
  captured.

```sh
sipnab -N --no-cli-print -I calls.pcap --retain-audio \
  --export-vcon-when "state == 'Completed'" --export-vcon-dir spool
```

sipnab prints one line for the directory:

```text
Wrote 1 vCon container(s) to 'spool'.
```

Add `--redact` and remove `--retain-audio`. The same command then writes
redacted containers without audio.

## Put the token in a file

vcon.store authenticates with a bearer token.

- Put the token alone in a file only you can read.
- The `vcon-store` kind sends it as `Authorization: Bearer <token>`.

```sh
# Run all of these, in order.
umask 077
printf '%s\n' "$VCON_STORE_TOKEN" > vcon-store.key
```

`$VCON_STORE_TOKEN` is the token vcon.store issued you.

- The forwarder never prints it.
- The forwarder removes it from any answer it keeps.
- Instead of a file, the `SIPNAB_VCON_FORWARD_AUTH` environment variable can
  hold the token.

The forwarder refuses a file that other users can read or write, and exits
`2`:

```text
--vcon-forward-auth-file 'vcon-store.key' can be read or written by other users (mode 0644); chmod 600 it
```

Run `chmod 600 vcon-store.key` and start the forwarder again.

## Send them

```sh
# Run all of these, in order.
STORE_URL=https://api.vcon.store
sipnab --vcon-forward spool --vcon-forward-kind vcon-store \
  --vcon-forward-url "$STORE_URL" --vcon-forward-auth-file vcon-store.key \
  --vcon-forward-once
echo "exit $?"
```

`--vcon-forward-kind vcon-store` does two things:

- It adds `/v1/vcons` to the base URL.
- It forms the header from the token.

It does not change the container. The same settings can live in `sipnab.toml`:

```toml
[vcon_forward]
kind = "vcon-store"
url = "https://api.vcon.store"
auth_file = "/etc/sipnab/vcon-store.key"
```

For each container the forwarder logs a `delivered` line with the store's
status and moves the file to `spool/delivered`. The log line has this form
(here from a run against a store on `127.0.0.1:18777`):

```text
INFO sipnab::app::vcon_forward: vCon forwarder watching 'spool', delivering to http://127.0.0.1:18777/v1/vcons
INFO sipnab::app::vcon_forward: delivered 1-1966_10.0.2.20-1cc03f180ff8a774.vcon.json: POST http://127.0.0.1:18777/v1/vcons answered 201; moved to 'spool/delivered'
```

With `--vcon-forward-once`, the exit status is:

- `0` when the store accepted every container, or there was none;
- `1` when the store refused any container, or any is still waiting;
- `3` when the store answered `401` or `403`.

Without `--vcon-forward-once`, the forwarder polls the spool until you stop it.

## Check what the store accepted and refused

A container the store refused is in `spool/failed`, with a `.error.json`
record beside it that holds the store's answer. To read the counts and those
answers without sending anything:

```sh
sipnab --vcon-spool-status spool
```

It prints one JSON document. Trimmed:

```text
{
  …
  "pending": 0,
  "delivered": 1,
  "failed": 1,
  "failures": [
    {
      "file": "1-1966_10.0.2.20-1cc03f180ff8a774.vcon.json",
      "record": {
        "at": "2026-10-16T11:47:53Z",
        "body": "{\"error\": \"vCon already exists\"}",
        "body_truncated": false,
        "file": "1-1966_10.0.2.20-1cc03f180ff8a774.vcon.json",
        "method": "POST",
        "reason": null,
        "status": 409,
        "url": "http://127.0.0.1:18777/v1/vcons"
      }
    }
  ],
  …
}
```

A capture run with `--mcp` or `--api` answers the same through:

- the MCP tool [`vcon_spool_status`](mcp-tools-vcon.md#vcon_spool_status),
- [`GET /v1/vcon/spool`](rest-api.md#get-v1vconspool).

## Replace a container the store already holds

vcon.store answers `409` to a `POST` of a uuid it already holds. By default
the forwarder treats that as a refusal:

- The container goes to `spool/failed`.
- The store's answer is in its `.error.json` record.
- `--vcon-forward-once` exits `1`.

The log line reads:

```text
WARN sipnab::app::vcon_forward: refused 1-1966_10.0.2.20-1cc03f180ff8a774.vcon.json: POST http://127.0.0.1:18777/v1/vcons answered 409; moved to 'spool/failed' beside 1-1966_10.0.2.20-1cc03f180ff8a774.vcon.json.error.json
```

To replace the held copy instead, name the store's `PUT` endpoint with
`--vcon-forward-replace-url`. The forwarder then sends the container there
after the `409`. `{uuid}` in the template becomes the container's uuid:

```sh
sipnab --vcon-forward spool --vcon-forward-kind vcon-store --vcon-forward-url https://api.vcon.store --vcon-forward-auth-file vcon-store.key --vcon-forward-replace-url 'https://api.vcon.store/v1/vcons/{uuid}'
```

Replacing is off by default, because it overwrites what the store holds.

To send a container that is already in `spool/failed` again, move it back into
`spool` and run the forwarder with `--vcon-forward-replace-url`.

The forwarder retries every `5xx` answer after a back-off and keeps the
container in `spool` meanwhile.

## Signatures

sipnab signs a container only when a `[[vcon.rule]]` asks it to:

- `sign_only = true` writes the signed form alone, a JWS with no encryption.
  See [Sign without encrypting](vcon.md#sign-without-encrypting).
- `encrypt_to` writes a signed container, encrypted. See
  [Encrypt what a rule writes](vcon.md#encrypt-what-a-rule-writes).

The containers `--export-vcon-dir` writes, as on this page, carry no
signature. A signature that the store adds covers what the store received. It
is not sipnab's, and it does not make an observation from a tap a recording.

sipnab records no consent, and a container carries none.

## Read a stored vCon back

`sipnab --vcon-fetch` reads a container back by its uuid, with the same key
file. The `vcon-store` kind:

- reads `/v1/vcons/{uuid}`,
- sends the key as `Authorization: Bearer <key>`,
- removes the `_meta` member the store adds.

So the file holds the container alone:

```sh
sipnab --vcon-fetch 018bcfe5-6800-8a6b-a667-78f1c5213800 --vcon-fetch-kind vcon-store --vcon-fetch-url https://api.vcon.store --vcon-fetch-auth-file vcon-store.key --vcon-fetch-out fetched
```

The fetcher writes `fetched/<uuid>.vcon.json`, mode 0600. When a file of that
name already exists, the fetcher skips that uuid and the run exits `1`. Add
`--vcon-fetch-overwrite` to replace the file.

More:
[Fetch a stored vCon](vcon.md#fetch-a-stored-vcon).

## When something does not work

- **The forwarder exits `3` and logs `answered 401`.**
  - The token in `vcon-store.key` is wrong or expired.
  - The forwarder moved no file. Every container is still in `spool`.
  - Fix the token and run it again. The log line reads:

    ```text
    ERROR sipnab::app::vcon_forward: vCon forwarder stopped: POST http://127.0.0.1:18777/v1/vcons answered 401 for 1-1966_10.0.2.20-1cc03f180ff8a774.vcon.json: "{"error":"unauthorized"}". A 401 refuses the credentials or the client for every container alike, so nothing more is sent and every container stays in the spool. Check the credential, and that nothing replaces the User-Agent: a Cloudflare front refuses some clients with a 403 whose body names error code 1010
    ```

- **The forwarder exits `3` and logs `403` with `error code: 1010`.**
  - The Cloudflare front of the store refused the request's client.
  - The forwarder sends `User-Agent: sipnab/<version>`. Check that nothing
    between it and the store replaces that header.
  - It moved no file, so run it again once you fix that.
- **A container lands in `spool/failed` with status `409` and `vCon already
  exists`.**
  - The store already holds that uuid (`--vcon-fetch` reads it back).
  - Follow [Replace a container the store already holds](#replace-a-container-the-store-already-holds).
- **Every container lands in `spool/failed` with status `400` and
  `extensions: Expected object, received array`.**
  - The store refuses `extensions` as the array of strings both vCon drafts
    define.
  - sipnab writes the array and the forwarder does not change it, so such a
    store does not accept sipnab's containers.
- **A container stays in `spool`, and the log says `answered 500; will
  retry`.**
  - The store failed to process the request.
  - The forwarder tries again after its back-off.
