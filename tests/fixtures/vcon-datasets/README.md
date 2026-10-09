# Public vCon datasets: the committed subset

The vcon-dev community publishes vCon containers as git repositories, listed at
<https://www.conserver.io/tools/vcon-datasets>. [`PINS.tsv`](PINS.tsv) pins
five of them to one commit each. The full datasets take about 2.3 GB of disk once fetched, so they
are not committed: `scripts/fetch-vcon-datasets.py` fetches them, and
`tests/vcon_dataset_corpus_test.rs` reads them when `SIPNAB_VCON_DATASETS`
names the directory. [The public vCon datasets](../../../docs/internals/testing.md#the-public-vcon-datasets)
says how to fetch and run them.

This directory holds four containers copied byte for byte from three of the
datasets, so the same checks run on every build. `tests/vcon_dataset_subset_test.rs`
pins what sipnab's schema validator reports for each one, checks that the
`jsonschema` reference agrees, and fetches each one back through
`--vcon-fetch-kind generic`. Each dataset directory carries that dataset's
`LICENSE` file and a README listing the source path and SHA-256 of every file.

| Directory | Files | What the files cover |
|---|---|---|
| [`ietf-meeting-vcons`](ietf-meeting-vcons/README.md) | 2 | a recording referenced by URL without `content_hash`; a transcript referenced by URL with `content_hash`; a container with no Dialog Object; inline JSON attachments |
| [`vcon-dataset-city-of-newport-ri`](vcon-dataset-city-of-newport-ri/README.md) | 1 | an inline `wtf_transcription` analysis of about 54 KB; a video recording referenced by URL |
| [`vcon-supreme-court-arguments`](vcon-supreme-court-arguments/README.md) | 1 | eleven parties with `meta`; a recording with `content_hash`; an inline `wtf_transcription` analysis |

## What was left out, and why

- **fake-vcons** and **tadhack-2025.** Each container in both datasets names
  its parties with a `gmail.com` address and a North American phone number.
  The data is synthetic (each party is marked `"validation": "synthetic"`),
  but the tadhack-2025 README states that the numbers and addresses were not
  checked against real subscribers. A committed copy could carry a real
  person's contact data, so none is committed. The opt-in corpus test reads
  both datasets in full.
- **ietf-meeting-vcons containers with an inline transcript.** The dataset's
  LICENSE notes that the underlying IETF meeting content is subject to the
  IETF Trust Legal Provisions. The two committed containers reference their
  transcript by URL, or have none, so they hold no meeting content.
- **ietf-meeting-vcons containers with participant addresses.** 6,169 of the
  8,181 containers carry an email address in a Party Object. The two committed
  containers carry none.
- **vcon-supreme-court-arguments containers with Oyez text.** 8,307 of the
  8,503 containers carry an Oyez transcript, and 3,709 carry Oyez case summary
  text. The committed container's
  transcript was made by the dataset's authors with Whisper from the Court's
  argument audio, and its case summary fields are empty.
