+++
title = "Keep the audio your store refuses"
date = 2026-08-27
description = "A vCon container carries its audio inline, and sipnab caps that at 5 MiB by default. Here is where the number came from, when to raise it, and how to say never inline media at all."

[extra]
kind = "howto"
+++

sipnab writes a call's audio into the vCon container itself, base64url-encoded.
That has a ceiling, and by default it is 5 MiB — about four minutes of
one-channel G.711. sipnab refuses a longer call, and the refusal appears in the
container's completeness caveat rather than passing as a call that had no
audio.

New in 0.5.128: you can change it.

```bash
sipnab -N -I ./captures \
  --export-vcon-when 'duration > 30' \
  --export-vcon-dir ./long/ \
  --vcon-max-inline-media 64
```

## Where 5 MiB came from

Not a guess, and not a round number somebody liked. A probe of a running vCon
store sent a container carrying roughly 12 MB of inline base64. The HTTP layer
answered **204**, PostgreSQL stored the row, and the file spool refused the
payload:

```text
16777749 > 10485760
```

Neither transport reported the partial write. The store told the producer "accepted"
while a storage backend dropped the audio.

The default sits at the 5 MiB the probe watched *land*, not at the
10485760-byte boundary observed to *fail*. The rest of the container — parties,
the full message trace, the completeness caveat — has to fit behind the ceiling
too, and a budget set at the failure boundary leaves it nothing.

## When to raise it

Raise it when you know what reads your containers. The number is a property of
a *consumer*, not of the format, and the consumer behind that measurement
publishes no per-container cap at all. If you write to a spool you control and
a bridge you wrote, 5 MiB is another operator's limit.

The flag is in MiB because that is how operators think about it. Every door
that builds a container reads the same value — batch export, the REST server
and the MCP server — so one call exported two ways cannot come back carrying
audio in one container and a refusal in the other.

## When to set it to zero

```bash
sipnab -N -I ./captures --export-vcon-when 'response_code >= 200' \
  --export-vcon-dir ./calls/ --vcon-max-inline-media 0 --retain-audio
```

`0` refuses every inline body. That is how you say "never inline media" without
turning the exporter off: the containers still carry parties, timing, the
message trace and the caveat, and the caveat still states that audio existed
and that sipnab refused it. It does not read as a call that had no audio, which is the
distinction that matters when somebody reviews the container six months later.

## Reading the refusal

Whatever budget is in force, a refusal names the size it refused and the budget
it enforced:

```text
INCOMPLETE: sipnab decoded 312.4 second(s) of audio for this dialog and
REFUSED to carry it: base64url of the 4998720 byte WAV is 6664960 bytes, over
the 5242880 byte budget this emitter enforces ...
```

It quotes the budget that was *actually applied*, not the compiled-in default —
otherwise an operator who raised the ceiling would go looking for a limit
nothing was enforcing.

The audio is not truncated and not silently dropped. It stayed in memory for
the run. What the container refuses is *carrying* it. To get the file itself,
ask the `export_audio` MCP tool for the dialog — it is an MCP tool rather than
a CLI flag, and it needs `--retain-audio` for the same reason the container
does.
