+++
title = "A size test for the MCP field cap measured the whole message instead of the field"
date = 2026-08-28
updated = 2026-10-11
description = "Why a test of sipnab's 256-byte cap on header values failed on macOS and passed on Linux while the cap worked on both, and the eight tests added to catch the same mistake."

[extra]
kind = "postmortem"
+++

## In short

sipnab shortens any single header value it hands to an AI assistant to 256
bytes. So one oversized header cannot fill the assistant's working space.

- A test of that limit measured the wrong piece of text.
  - It measured the whole message record around the header.
  - It did not measure the header value itself.
- That record is longer on macOS than on Linux.
  - So the test failed on macOS and passed on Linux.
  - The limit worked correctly on both.
- The test now picks out the header value itself.
- Eight further tests check for the same mistake.

## What happened

CI is the automated build-and-test service. The CI job `Check (macos-latest)`
failed on the test `an_oversized_header_is_bounded_in_the_response` in
`tests/mcp_output_injection_test.rs`.

- The comment added with the fix records that four commits ran red on it.
- The same test passed on Linux.

The test works this way:

- It builds a capture holding one SIP INVITE. The INVITE is the message that
  starts a call.
- Its `User-Agent` header is 4096 bytes long. That header names the caller's
  software.
- It asks sipnab's MCP server for that message with the `get_message` tool. The
  MCP server is the interface an AI assistant uses to query sipnab.
- It checks that the header value in the answer is short.

The fix is commit 1ccf1f8a, dated 2026-08-28, first released in 0.5.130.

## Why it happened

sipnab caps each header value at `MAX_FIELD_BYTES`, which is 256
(`src/mcp/shape.rs`).

- A capped value ends with the marker `…[truncated]`.
- sipnab wraps the whole value in the fence markers `⟦untrusted-capture-data⟧`
  and `⟦/untrusted-capture-data⟧`.
  - They tell the assistant that the text came from the network and not from
    sipnab.
- With the markers, the capped `User-Agent` value is 327 bytes.

The answer to `get_message` contains the long `User-Agent` text in two
strings:

- the fenced header value,
- an unfenced record of the whole message.

The test took the first string containing the payload. That was the whole
message record. The test required it to be at most 1024 bytes.

That record's size depends on two things:

- the other headers,
- the capture file's path, which includes the temporary directory.

The comment in the test file records the sizes:

| Platform | String the test measured | Result against 1024 bytes |
|---|---:|---|
| Linux | 992 bytes | passed |
| macOS | 1036 bytes | failed |

- The header value itself was 327 bytes on both.
- The temporary directory path on macOS is longer. That made the message record
  longer.
- The cap was never what the test measured.

## What changed

The test now selects the string that starts with the fence marker. sipnab
fences each value on its own. So a string that starts with the marker is a
single value. It is not a record that contains one:

```rust
let ua = strings
    .iter()
    .filter(|s| s.contains("UUUU"))
    .find(|s| s.starts_with(sipnab::mcp::shape::UNTRUSTED_OPEN))
```

The test computes its size limit from the constant. So a change to the cap
changes the test with it:

```rust
let ceiling = sipnab::mcp::shape::MAX_FIELD_BYTES + 128;
```

The 4096-byte input is below the parser's 8 KiB header-line limit
(`DEFAULT_MAX_HEADER_LINE_LEN` in `src/sip/parser.rs`).

- Above that limit sipnab rejects the whole message.
- The test would then check a message the cap never processed.

The change added eight tests to the same file. Each checks one condition:

| Test | What it checks |
|---|---|
| `the_response_carries_an_oversized_field_in_more_than_one_string` | The payload appears in at least two strings, the condition that made the original test ambiguous. |
| `the_container_is_larger_than_the_field_it_encloses` | The message record is larger than the header value. |
| `the_field_cap_is_independent_of_the_capture_path_length` | A longer capture path changes the record's size and leaves the header value's size unchanged. |
| `the_capped_field_is_a_fraction_of_the_header_that_produced_it` | The capped value is under a quarter of the 4096-byte input and more than half the cap. |
| `a_capped_field_declares_that_it_was_cut` | A shortened value carries the truncation marker. |
| `capping_a_field_does_not_strip_its_closing_fence` | The closing fence marker survives the cap. |
| `no_string_in_the_response_carries_the_header_whole` | No string in the answer carries more than 256 bytes of the payload in one run. |
| `the_oversized_header_fixture_actually_reaches_the_response` | The test input reaches the answer, so the other checks are not empty. |

On 2026-10-11 a run disabled the cap in a copy of the source at commit
6e2cbab2. It replaced the size check in `sanitize_field` by `true`. Four tests
failed:

- `an_oversized_header_is_bounded_in_the_response`
- three of the eight:
  - `a_capped_field_declares_that_it_was_cut`
  - `no_string_in_the_response_carries_the_header_whole`
  - `the_capped_field_is_a_fraction_of_the_header_that_produced_it`

The other five check how sipnab selects values, not the cap's size.

In the same run on Linux, the message record that the original test measured
was 1444 bytes. So a fixed 1024-byte limit would now fail on Linux too.

## What you can check yourself

From a checkout of the sipnab repository, run the test file with the `full`
feature set. The file compiles only with the `mcp` feature:

```sh
cargo test --features full --test mcp_output_injection_test -- --test-threads=1
```

The test lines of that run at commit 6e2cbab2 (0.5.211):

```text
running 13 tests
test a_capped_field_declares_that_it_was_cut ... ok
test an_oversized_header_is_bounded_in_the_response ... ok
test an_rtpmap_encoding_name_carrying_a_sentence_is_fenced ... ok
test capping_a_field_does_not_strip_its_closing_fence ... ok
test get_dialog_explains_the_markers_it_uses ... ok
test get_dialog_fences_the_messages_it_returns ... ok
test no_string_in_the_response_carries_the_header_whole ... ok
test no_tool_result_carries_a_control_character_out_of_a_header ... ok
test the_capped_field_is_a_fraction_of_the_header_that_produced_it ... ok
test the_container_is_larger_than_the_field_it_encloses ... ok
test the_field_cap_is_independent_of_the_capture_path_length ... ok
test the_oversized_header_fixture_actually_reaches_the_response ... ok
test the_response_carries_an_oversized_field_in_more_than_one_string ... ok

test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 6.36s
```

## Terms used here

- **MCP** (Model Context Protocol): the protocol an AI assistant uses to call
  sipnab's tools.
- **SIP** (Session Initiation Protocol): the signaling protocol that sets up
  and ends phone calls.
- **INVITE**: the SIP message that starts a call.
- **Capture**: a file of recorded network packets (a pcap file).
- **CI** (continuous integration): the service that builds and tests every
  commit on Linux and macOS.
- **Job**: one CI run on one platform. It "runs red" when a test fails.
- **Commit**: one recorded change to the source code.
- **Assertion**: the line in a test that states what must be true.
- **Fence**: the pair of markers sipnab puts around text that came from the
  network.
- **Field cap**: the 256-byte limit on one header value in an MCP answer.
- **Payload**: the test input, here 4096 copies of the letter `U`.
- **KiB**: 1024 bytes.
- **JSON**: the text format of MCP answers.

## Related guides

- [Untrusted capture text](@/docs/mcp-protocol.md#untrusted-capture-text):
  which values sipnab fences.
- [What else a fenced value cannot carry](@/docs/mcp-protocol.md#what-else-a-fenced-value-cannot-carry):
  the 256-byte field cap and the truncation marker.
- [Response bounding](@/docs/mcp-tools.md#response-bounding): the other size
  limits on MCP answers.
- [Fixtures and corpora](@/docs/internals/testing.md#fixtures-and-corpora):
  how the test suite builds its inputs.
