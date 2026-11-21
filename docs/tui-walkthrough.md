# Walk through the terminal UI

Your first analysis in the interactive TUI, step by step — open a capture, read
the ladder, measure a delay, and inspect RTP.

> New to sipnab? Start here. This is a guided first run through the interactive
> TUI.
>
> - It names every key you press.
> - The full reference lives in [Keybindings](keybindings.md).
> - If you prefer the command line, follow
>   [Triage a capture from the command line](first-cli-triage.md) instead.
> - The [Glossary](glossary.md) defines any term you do not recognize.

## Before you start

- **sipnab with the `tui` feature**, which every release binary and package
  has. `sipnab --version` lists the features of your build. A build without
  `tui` draws no interface and reads the capture as `sipnab -N` does.
  [Installing sipnab](install.md) has every install route.
- **A terminal.** sipnab draws the interface on the terminal it starts in, and
  exits with an error when it has none.
- **No privileges** to read a capture file. Watching an interface needs root
  or the capture capabilities that
  [Capture live traffic without root](install.md#capture-live-traffic-without-root)
  grants once.
- **No change on any other system.** Every step reads one downloaded file.

## Open a capture

No capture handy? Download the sample call the website uses:

```bash
curl -LO https://sipnab.com/demos/sample-call.pcap
```

Point sipnab at a pcap (packet capture) file. It drops you straight into the
**Call List**:

```bash
sipnab -I sample-call.pcap
```

To watch live traffic on an interface instead, run it with `sudo`. Opening a
capture device needs privilege:

```bash
sudo sipnab -d eth0
```

Or start with no argument at all. Then open a file from inside the TUI with
`O` (the File Open dialog):

```bash
sipnab
```

You can open a different capture at any time with `O`. You do not need to restart.

## Find your way around the call list

The Call List is the home view. It has one row per SIP
[dialog](glossary.md#dialog) (every message that shares a Call-ID). Each row
shows:

- method,
- endpoints,
- state,
- message count,
- [PDD](glossary.md#pdd) (post-dial delay, the wait between the INVITE and the
  first ringing response).

The three lines above it say what you are looking at:

- the source (`File: capture.pcap` or `Live capture: eth0`), with how many
  dialogs the list shows out of how many sipnab holds,
- then the capture (BPF) filter,
- then the view filter.

The bar at the bottom lists the keys of the view you are in. `F1` opens the
help from any view.

- `j` / `k` (or `Down` / `Up`) move the selection. `PgUp` / `PgDn`, `Home`, `End` jump around.
- `<` / `>` sort by the previous / next column. `Z` reverses the direction.
  - Sort by **State** to bring `Failed` calls to the top.
  - Sort by **PDD** to find slow setups.
- `t` cycles the timestamp mode (absolute → delta from previous → delta from first → scaled). Delta from previous is the one that makes latency spikes jump out.
- Too many columns, or missing one you want (Source IP, PDD)? `F10` opens the column selector.

Land on the call you care about, then press `Enter`.

### Find the dialogs that are not over

On a busy capture most rows are calls that ended and registrations that
lapsed. Press `d` to keep only the dialogs still in progress: calls up or
ringing, valid registrations, active subscriptions and open transactions.

- What you need: the TUI on any capture; nothing changes on another system.
- Steps: start the TUI and press `d` on the call list.

```sh
sipnab -I capture.pcap
```

- Check it: status line 1 says `Showing: not over`, and `Dialogs: N shown of M` drops.
- `d` again shows every dialog.
- A REGISTER counts as over when its challenge got no REGISTER in answer, or
  when its registration expired by the capture's clock (the newest message).
- When a dialog you expect stays hidden, press `d` to show all, then open it
  with `Enter` and read its last message: a final response ended it.
- In the call flow, `d` still cycles the SDP display.

### Watch the dialogs updated last

`L` sorts the call list by each dialog's last message, the one updated last
at the bottom. Use it on a live capture to watch where traffic happens now.

- What you need: the TUI; nothing changes on another system.
- Steps: press `L` on the call list; press `L` again to return to `#` order.

```sh
sipnab -d eth0
```

- Check it: status line 1 says `Sort: Last update ▲`; back in `#` order it says `Sort: #`.
- When the order does not seem to change, check that autoscroll (`A`) is not
  moving the selection, and that a search or filter is not hiding the rows.

## Set how the TUI starts

The `[display]` section of the configuration file sets the starting state of
keys you would otherwise press after every start.

- What you need: a writable configuration file (see
  [Configuration reference](config-reference.md)); nothing changes on another
  system.
- Steps: add the keys you want under `[display]`, then start the TUI.

```toml
[display]
fold = false          # every retransmission and auth retry is its own arrow
autoscroll = false    # the selection stays where you put it
sdp_display = "full"  # none, summary or full; `d` still cycles it
color_mode = "cseq"   # method, call_id or cseq; `c` still cycles it
extended_flow = true  # open the multi-leg flow by default
```

- Check it: open a call flow; with `fold = false` the ladder shows each
  retransmission as its own row, and the F2 Mermaid export does the same.
- When sipnab refuses to start with `[display] sdp_display must be one of`
  or `[display] color_mode must be one of`, correct the value: the spellings
  are lower case. See [Error reference](errors.md).
- `[display] autoscroll` sets the starting state; the `autoscroll` key
  binding (`A` by default) toggles it.

## Use sngrep's keys and colors

sngrep mode is for readers who know sngrep's keys. On the call list, call
flow, raw message and message compare screens each sngrep key does what it
does in sngrep, and those screens take sngrep's colors and bottom key bar.
The sipnab commands whose keys sngrep uses move to free keys. Without the
mode the TUI keeps sipnab's own keys and colors.

- What you need: the TUI; nothing changes on another system. For the
  permanent setting, a writable configuration file (see
  [Configuration reference](config-reference.md)).
- Steps: start the TUI with `--sngrep-mode`.

```sh
sipnab -I capture.pcap --sngrep-mode
```

- To keep it on, set the key; `--no-sngrep-mode` then turns it off for one run.

```toml
[display]
sngrep_mode = true
```

- The mode starts with autoscroll off, every retransmission as its own
  arrow, Call-ID colors, the multi-leg flow and sngrep's SDP form. A
  `[display]` key you set wins over each of these.
- Check it: the bottom bar reads `Esc Quit  F1 Help  Enter Open call  Space Check`,
  and `F1` opens on the sngrep key map. In a call flow, `9` and `0` make the
  raw pane wider and narrower, and the status line names its width.
- The key tables are in [Keybindings: sngrep mode](keybindings.md#sngrep-mode),
  with the sipnab keys that move.
- With `NO_COLOR` set, the keys, help and key bar stay sngrep's and sipnab
  draws no color; the current row is in reverse video.
- When the status line at start says `Ignoring [display] sdp_display = "sngrep"`,
  the `sngrep` SDP form needs the mode: start with `--sngrep-mode`, set
  `sngrep_mode = true`, or pick `none`, `summary` or `full`.
- When a key does something other than in sngrep, check that you are on one
  of the four screens above: every other view keeps sipnab's keys.

## Read the call-flow ladder

`Enter` opens the **Call Flow**. It is a ladder diagram of the dialog across
every host it touched (UAC → proxy → UAS). A detail pane sits beside it.

- `j` / `k` walk message-to-message. The detail pane updates to show the parsed message under the cursor.
- `d` cycles how the detail pane shows SDP (hidden / summary / full).
- `w` toggles line wrapping in the detail pane.
  - With wrap off, long lines truncate and a horizontal scrollbar appears.
  - Press `Tab` to put the cursor in the detail pane. `Left` / `Right` then scroll it sideways.
  - Without that focus, the same two keys resize the detail pane instead.
  - `R` hides or shows it.
- `Enter` on a message opens the full-screen **Raw Message** view.
  - `/` searches within it.
  - `n` / `N` jump between matches.
  - `Esc` returns.
- `c` recolors the ladder by method, Call-ID, or CSeq. `t` shares the timestamp mode with the Call List.

`Esc` takes you back to the Call List at any time.

## Measure the delay between two messages

This is the trick most people come to sipnab for. In the Call Flow:

- Move to the first message (say the `INVITE`). Press `m` to drop a **mark**.
- Navigate to a later message (the `200 OK`). A **delta badge** appears. It shows the elapsed time between the mark and your current position.
- Press `M` to clear the mark.

Now you can read "how long from INVITE to 200 OK?" straight off the ladder.
You do not need to do timestamp math in your head.

## Compare two messages side by side

Suspect a header changed across a retransmit or a proxy hop?

- Press `Space` on one message.
- Then press `Space` on another. This opens the **Message Diff**, a
  line-by-line comparison.
- `Esc` returns to the ladder.

## Search and filter

- `/` searches the current view (Call List, Raw Message, or RTP Streams).
- `F7` opens the **Filter dialog**.
  - Its fields are From user, To user, Source IP, Destination IP, Text in
    message, Header, After, Before, Named filter and Expression, and a box
    per method.
  - After and Before take an [RFC 3339](https://www.rfc-editor.org/rfc/rfc3339.html)
    time, such as `2023-11-14T22:13:25Z`, and keep the calls that started in
    between.
  - Header takes `Name: text`, or a bare header name to keep the calls that
    carry it.
  - Named filter takes the names of the `[filters]` entries in your
    configuration file. Through them, the dialog applies any
    [Filter DSL](filter-dsl.md#named-filters) expression, for example
    `rtp.mos < 3.0`. Without a configuration file, it shows
    `none in [filters]`.
  - Expression takes any Filter DSL expression typed as it is. See
    [Filter with an expression](#filter-with-an-expression).
- Status line 3 shows the filter the dialog built as a summary, such as
  `F7: 7 methods, From~alice · F full`.
  - `F` switches between the summary and the full expression, in every view.
  - `view_filter_detail = "full"` under
    [`[display]`](config-reference.md#display) opens the TUI with the full
    expression.
- `F9` clears the view filter and any kept search.
- `i` prunes the dialogs that do *not* match, keeping only the matches.
- `I` prunes the ones that do.

## Filter with an expression

The `F7` dialog's **Expression** field takes a
[Filter DSL](filter-dsl.md) expression typed as it is. Use it for a filter
the other fields cannot say: an exclusion, a message count, `OR`, or
parentheses. It needs no restart and no configuration file.

**What you need:**

- **sipnab with the `tui` feature**, as in [Before you start](#before-you-start).
- **No change on any other system.** The expression filters the calls the
  TUI already holds.

**Steps:**

1. Open a capture or start a live capture, as in
   [Open a capture](#open-a-capture).
2. Press `F7`. The dialog opens with the cursor in **From user**.
3. Press `Tab` nine times. The cursor moves to **Expression**, the field
   under Named filter.
4. Type the expression. It takes the text `--filter` takes:
   - `payload =~ 'X-Foo' AND NOT payload =~ 'OPTIONS' AND msg_count > 5`
     keeps the calls that carry `X-Foo`, never mention `OPTIONS`, and have
     more than five messages.
   - `msg_count < 3`, `msg_count > 5` and `msg_count == 2` compare the
     number of messages in a call. Equality is `==`.
   - `payload =~ '(?i)x-foo'` matches either case.
   - `OR` and parentheses group terms:
     `payload =~ 'X-Foo' AND (msg_count < 3 OR NOT payload =~ 'OPTIONS')`.
   - `@name` uses a [`[filters]`](config-reference.md#filters) entry, and an
     alias name such as `one-way` stands for its expansion.

   ```text
   │  Named filter:    [none in [filters]                                  ]  │
   │  Expression:      [from.user =~ '1003' OR msg_count > 3               ]  │
   │  ──────────────────────────────────────────────────────────────────────  │
   │  All       [*]                                                           │
   ```

5. Press `Enter`. The dialog closes and the call list keeps only the calls
   the expression and every other field of the dialog select. The filter
   applies to calls that arrive later too.

A session started with `--filter` or with `expression` under
[`[filter]`](config-reference.md#filter) opens with that text in the
Expression field, already applied. Edit it there.

**Check that it worked:** status line 3 names the expression after `expr`, and the count on line 1
drops:

```text
 Live capture: any    Dialogs: 2 shown of 3    Autoscroll: on
 Capture filter (BPF): none
 View filter: F7: expr from.user =~ '1003' OR msg_count > 3 · F full
```

- `F` shows the full expression that runs. The other fields come first, and
  the typed expression in parentheses after `AND`.
- To remove the expression, open `F7`, empty the field, and press `Enter`.
  `F9` clears every field and the filter at once.

**When it does not work:**

- **The dialog stays open with `⚠ Expression error:`.** The parser refused
  the text. The line gives its reason and position, the cursor sits at that
  position, and the filter in force before stays until you apply a valid
  one. When the parser has a hint, it appears under the key line:

  ```text
  │  ⚠ Expression error: unexpected input at position 18: 'msgcount'         │
  │  Tab move · Enter apply · Esc cancel · F1 fields                         │
  │  hint: unknown field 'msgcount' — did you mean 'msg_count'?              │
  ```

- **The dialog refuses `msg_count = 5`.** The DSL writes equality as `==`.
- **`'@name' is not a defined filter`.** The name is not under `[filters]`
  in the configuration file this session loaded. The message lists the names
  that are.
- **A text match finds nothing.** A regex is case-sensitive. Add `(?i)` at
  the start of the pattern to ignore case.
- **Nothing shows at all.** Every method box is clear. That shows no calls
  whatever the expression says. Check **All**.

### Use an earlier expression again

The Expression field keeps the expressions you applied in this session, so
you can go back to one without typing it again.

**What you need:** a session where you applied at least one expression, as
in the steps above. Nothing changes on any other system.

**Steps:**

1. Press `F7` and move to **Expression** (`Tab` nine times).
2. Press `Up`. The field shows the expression you applied last, with the
   cursor at its end. Each further `Up` shows the one applied before it.
3. Press `Down` to step back toward the newest. One `Down` past the newest
   puts back the text the field held before the first `Up`.
4. Edit the recalled text if you need to. The edit changes the field only.
   The history keeps the expression as you applied it.
5. Press `Enter` to apply it.

The history holds only expressions the dialog applied, so each one parsed.
It keeps the newest 50, each once: applying an expression again moves it to
the front. It lasts for the session and is not saved. An expression the
session started with from `--filter` or `[filter] expression` is the first
entry.

**Check that it worked:** status line 3 names the recalled expression after
`expr`, as for a typed one.

**When it does not work:**

- **`Up` moves to Named filter instead.** The history is empty, or the field
  already shows the oldest entry. Apply an expression first.
- **An expression is missing.** The dialog refused it, so it never entered
  the history, or 50 newer ones pushed it out.

### Look up the fields and operators

`F1` in the dialog shows every field name, comparison operator and combining
word the [Filter DSL](filter-dsl.md) takes. The list comes from the parser,
so it names exactly what the Expression field accepts.

**What you need:** the `F7` dialog open. Nothing changes on any other system.

**Steps:**

1. Press `F7`.
2. Press `F1`. The list takes the place of the method boxes and the buttons.
   The text fields stay, and typing and `Enter` work as before.
3. Press `F1` or `Esc` to hide the list. With the list hidden, `Esc` cancels
   the dialog as usual.

```text
│  ──────────────────────────────────────────────────────────────────────  │
│  Filter DSL · F1 or Esc closes this help                                 │
│  Fields: from.user to.user from.host to.host from.uri to.uri ruri        │
```

The list is behind a key because the dialog has no free row: the fields
take about seven rows of the 23-row dialog, which would no longer fit an
80x24 terminal with its key line. The values each field takes are in the
[Filter DSL reference](filter-dsl.md).

**Check that it worked:** the dialog shows lines that start `Fields:`,
`Operators:` and `Combine:`.

**When it does not work:** `F1` opens the main help instead when no dialog is
open. Press `F7` first.

### Run the same filter from a shell

`Y` in the call list turns the filter in force into one `sipnab` command line
with `--filter`, and copies it. Run it later, or on another host with the same
capture, to see the same call list.

**What you need:**

- A view filter in force: from the `F7` fields, a named filter, an
  expression, or a time window.
- For the copy to reach your system clipboard, a terminal that accepts
  OSC 52, as in [Copying text](keybindings.md#copying-text). Without one, the
  command is still shown.
- Nothing changes on any other system.

**Steps:**

1. Apply a filter with `F7`, as above.
2. Close the dialog and press `Y` in the call list.
3. A **Command line** box shows the command, and the status line reports the
   copy:

   ```text
   sipnab -I sample-call.pcap --filter 'from.user =~ '\''1003'\'' OR msg_count > 3'
   ```

4. Press `Esc` or `Enter` to close the box. Paste the command into a shell.

The filter in the command is the one the call list runs. It holds every `F7`
field and the full text of each named filter, and After and Before become
`time` comparisons, so the command needs no `[filters]` table. sipnab quotes
each word for a POSIX shell: a `'` in the text becomes `'\''`.

The source words are the ones the session read: `-I` and the file for one
capture file (or the last file `O` opened), each `-I` input and
`--recursive` for several, or `-d` and `-L` for a live capture. The command
leaves out the other options of the run, such as a BPF capture filter or a
port range. Add them to the command if the session used them.

**Check that it worked:** run the command. The new session opens with the
filter in its Expression field and applied, and status line 1 shows the same
count of calls.

**When it does not work:**

- **`No view filter is in force`.** Nothing narrows the call list. Apply a
  filter with `F7` first.
- **`Clipboard error`.** No clipboard took the text. The box still shows the
  command: press `F12` to turn mouse capture off and select it with the mouse.
- **`not valid UTF-8`.** Text cannot hold the capture file's path.
  Rename the file or open it from a path that can.
- **The new session shows more calls.** The run used an option the command
  does not carry, such as a capture filter. Add it to the command.

### Save the dialog's filter under a name

`F2` in the filter dialog saves the dialog's filter as a `[filters]` entry
of your config file. The name is then listed beside **Named filter**, and
`@name` works wherever sipnab takes a filter: `--filter`, the REST `filter`
parameter, an MCP tool's `filter`, and the dialog itself. The REST API and
MCP server of the same session resolve the name at once, with no restart.

**What you need:**

- A config file the session may write: the file the run loaded, or, when it
  loaded none, `~/.config/sipnab/sipnab.toml` (sipnab creates it). The same
  file `F10` saves the column layout to. A run that loaded
  `/etc/sipnab/sipnab.toml` cannot save to a file. Without a file sipnab
  can write, the name still works, for this session only (see below).
- Nothing changes on any other system.

**Steps:**

1. Press `F7` and fill the fields, the Named filter, or the Expression, as
   above. After and Before stay empty: an entry holds an expression only.
2. Press `F2`. The key line becomes a prompt:

   ```text
   Save as: @▁ · Enter save · Esc back
   ```

3. Type the name, for example `alice-big`, and press `Enter`. The dialog
   shows `Saved @alice-big to` and the file's path, and the name joins the
   list beside Named filter. A path in your home directory starts with `~`.
   A notice or refusal wider than the dialog continues on the next rows.
4. Press `Esc` to close the dialog, or `Enter` to apply the filter as well.
   Saving does not apply it.

A name is 1 to 64 ASCII letters, digits, `-` or `_`, starting with a letter
or digit. sipnab drops a leading `@` you type. The entry is the expression the
dialog builds, with each `@name` and the Named filter kept as references, so
it follows the entries it names. sipnab saves a built-in alias typed as the
whole Expression, such as `problems`, as `@problems`. sipnab adds the one
line to `[filters]` and keeps every comment and other setting of the file,
its mode, and its group when you belong to that group. A file sipnab creates is readable and writable by you
only (mode `0600`):

```toml
[filters]
alice-big = "from.user =~ 'alice' AND (msg_count > 5)"
```

**Check that it worked:** open the file and find the line under
`[filters]`. Then type the name in Named filter and press `Enter`: the call
list shows the calls the dialog's filter selected. A new session lists the
name beside Named filter too.

**When it does not work:**

- **`Nothing to save`.** Every field is empty, or the dialog has no SIP
  method checked. Fill a field, or check a method.
- **`A named filter holds no time window`.** Clear After and Before, then
  press `F2` again.
- **`already defines 'name'`.** The run, or the file, already has that
  name. Choose another name, or edit the entry in the file. A save never
  replaces an entry.
- **`is not usable`** or **`is a built-in alias`.** The name breaks the
  rule above or is one of the built-in aliases. Choose another name.
- **`is not a valid filter expression`.** The Expression does not parse.
  `Esc` closes the prompt; correct the field and press `F2` again.
- **`Kept @name for this session only`.** sipnab could not write a config
  file, so the name is in the running session only: listed beside Named
  filter and usable as `@name` in the dialog, the REST API and the MCP
  server, until sipnab exits. sipnab never writes it later. The note names
  the reason:
  - `cannot create <directory>`: a directory on the way to the file does
    not exist, and you may not create it.
  - `cannot write <file>`: you may not write the file (its mode, or another
    user owns it), or you may not write its directory. sipnab does not
    replace a file you may not write.
  - `cannot read <file>`: you may not read the file. sipnab also could not
    check whether the file already defines the name.
  - `not saved: the settings in use come from /etc/sipnab/sipnab.toml`, or
    no `$HOME`: there is no file to write.

  To keep the name, start sipnab with `--config <writable file>` or set
  `$SIPNAB_CONFIG` to a file you may write, or fix the permissions of the
  file or directory the note names. Then add the entry the note shows under
  `[filters]` in that file. `F3` copies the entry line to the clipboard, and
  `Esc` closes the note. sipnab refuses a second save of the same name in
  the same session as a duplicate.
- **`Save failed`.** sipnab could not write the file for a reason other
  than permission, such as a full disk, and nothing changed. The message
  names the file and the cause.
- **`not valid TOML`** or **`[filters] is not a table`.** The config file
  has an error; nothing changed. Fix the file and press `F2` again.
- **`Refusing to save`.** The path is a directory, or the file is not valid
  UTF-8; nothing changed.
- **A save writes, but another sipnab session saved to the same file at the
  same moment.** sipnab reads the file just before it writes it, so it
  finds a name the other session saved earlier and refuses it as a
  duplicate. Two
  saves that run at the same instant can still lose one of them: check the
  file, and save the lost name again.

## Find the calls sipnab diagnosed

The Call List marks a call sipnab diagnosed as broken. Open
[`tests/pcap-samples/sip-problem-call.pcap`](https://github.com/NormB/sipnab/raw/main/tests/pcap-samples/sip-problem-call.pcap) from a source checkout to see it:

```bash
sipnab -I tests/pcap-samples/sip-problem-call.pcap
```

```text
  # ▲    Method    From  To    Source              Destination         State      Msgs +Prev    PDD
> [ ] 1  INVITE    alice bob   192.0.2.10          192.0.2.20          Completed  7    +0.000s  850ms
  [ ] 2  INVITE    carol dave  192.0.2.30          192.0.2.40          FAILED ⚠   4    +3.000s
  [ ] 3  INVITE    erin  frank 198.51.100.30       198.51.100.40       FAILED ⚠   4    +3.000s
```

- `⚠` beside the state marks a call with a diagnosis.
- Open the call with `Enter`. The ladder tags the message the diagnosis rests
  on. For the busy call it is `486 Busy Here [FAILURE]`.
- The same diagnosis is in `--report` and `--json-dialogs`, and in the
  `signaling_diagnosis` of every dialog sipnab reports over REST and MCP. See
  [Output formats](output-formats.md).

## Ask questions about the whole capture

From the Call List, one key opens a view that answers a question about every
call the list holds:

| Key | View | What it answers |
|---|---|---|
| `g` | Top talkers | Which source addresses took part in the most calls, and how many of their INVITEs the far end answered or failed |
| `m` | Carrier metrics | ASR, NER and ACD for each destination address |
| `b` | Call volume | How many calls started in each minute |
| `e` | Endpoint | Everything the selected call's source address did |
| `c` | Compare two calls | How two calls differ. Star exactly two with `Space` first |
| `o` | SDP offer/answer timeline | Each offer and answer of the selected call, with codecs, address and direction |
| `f` | RFC conformance | The conformance findings of the selected call |
| `a` | Security findings | The alerts of the detectors the run armed |
| `h` | Capture health | Drops, undecodable frames, and the HEP listener's senders |

`Esc` returns to the Call List.

With the calls from `sip-problem-call.pcap`, `m` shows:

```text
┌ Carrier metrics (by destination IP) ───────────────────────────────────────────────────────────────────────┐
│Destination IP            Calls      ASR      NER       ACD                                                 │
│192.0.2.20                    1   100.0%   100.0%     17.9s                                                 │
│192.0.2.40                    1     0.0%   100.0%         —                                                 │
│192.0.2.60                    1     0.0%     0.0%         —                                                 │
│198.51.100.40                 1     0.0%   100.0%         —                                                 │
│203.0.113.40                  1     0.0%     0.0%         —                                                 │
```

The callee at `192.0.2.40` refused the call as busy, which counts toward NER and not
ASR. The calls to `192.0.2.60` and `203.0.113.40` failed with `503` and `404`,
which count toward neither.

Star the answered call and the busy one, then press `c`:

```text
┌ Compare two calls ─────────────────────────────────────────────────────────────────────────────────────────┐
│  A: completed-9f8e7d@192.0.2.10                                                                            │
│  B: busy-3a2b1c@192.0.2.30                                                                                 │
│                                                                                                            │
│  State         A: Completed                   B: Failed  (differs)                                         │
│  Final status  A: 200                         B: 486  (differs)                                            │
│  Messages      A: 7                           B: 4  (differs)                                              │
│  Methods       A: ACK,BYE,INVITE              B: ACK,INVITE  (differs)                                     │
│                                                                                                            │
│  Differences: state, final status, message count, methods                                                  │
│  B hints:                                                                                                  │
│    - Call failed: 486 Busy Here.                                                                           │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

These views answer about the calls the terminal holds. The command-line
flags answer the same questions from a script, with more dimensions to group
by. See [Answer questions about a capture](capture-queries.md).
[Keybindings](keybindings.md) lists the keys inside each view.

## Inspect RTP quality

Press `Tab` to switch from the Call List to the **RTP Streams** view. It lists
every media stream with:

- codec,
- packet count,
- [jitter](glossary.md#jitter) (how much packet spacing varies),
- loss.

Streams flagged `orphan` have no matching SIP dialog. That is often a sign that
NAT or a SIP-aware router rewrote the media address.

From a Call Flow, `r` opens the same view narrowed to that call's streams.

- `a` switches between that call's streams and every stream.
- `Esc` returns to the Call Flow.
- A stream is a call's when an SDP sipnab captured names the stream's address
  and port.
- A stream with NAT on both ends, or one sent over ICE or TURN, can stay
  unlinked. Status line 3 counts those, and `a` shows them.

Press `Enter` on a stream to open **Stream Detail**. You can also press it on
a stream's row in the Call Flow (`F6`). Stream Detail shows:

- [MOS](glossary.md#mos) (mean opinion score, an estimate of how the call
  sounded),
- jitter statistics,
- quality intervals,
- burst/gap analysis,
- silence detection,
- MOS/jitter sparklines.

From the RTP Streams view, `D` opens the **Quality dashboard**, which ranks
the streams worst MOS first. `L` there, or in Stream Detail, opens the
selected stream's **Packet loss map**. [Measure call quality](call-quality.md#watch-quality-in-the-terminal-ui)
shows both.

A stream whose far end sent RTCP XR gains a **Reported by far end (RTCP XR)**
section at the bottom.

- It holds that endpoint's own R-factor, MOS-LQ, MOS-CQ, delays and discard
  rate.
- Everything above that section is what sipnab measured. Nothing in the
  section moves those numbers.

With an `audio` build, `Shift+P` plays the stream (G.711 or Opus). `Esc` returns to the
RTP Streams list. `Tab` there switches back to the Call List.

## Follow each RTP stream in the call flow

Press `F6` (or `Ctrl+R`) in the Call Flow to draw the call's RTP streams in the
ladder.

- RTP (Real-time Transport Protocol) carries the call's audio and video.
  - A stream is one direction of it: packets from one address and port to
    another.
  - A stream belongs to the call when an SDP sipnab captured names its address
    and port. The `r` view uses the same link.
- Each stream gets its own row, at the time of its first packet, among the SIP
  messages.
- The row is an arrow from the sender's column to the receiver's column.
  - A double line (`═`) marks it as media rather than a SIP message.
- The label reads like `RTP (PCMA) 250 6000→33912`:
  - the codec, or `PT` and the RTP payload type number when sipnab cannot name
    the codec;
  - the packet count, which grows while a live capture runs;
  - the source port and the destination port.
- `one-way` before the count marks a stream with no reverse stream.
  - The reverse stream runs from the receiver's address and port back to the
    sender's.
  - A call whose streams are all paired shows no mark.
- A media address that no SIP message uses gets a column of its own, labeled
  with the bare IP address.
  - This is how a media relay shows, such as rtpengine on the capture host.
    Media arrives at the relay's address and leaves from it, so the ladder
    shows both legs of the media path.
  - A media address whose IP a SIP column already has uses that column,
    whatever the port.
- The extended view (`x`) draws the streams of every leg it shows. A
  multi-selection flow draws the streams of every call it merges.
- In a gap too narrow for the whole label, sipnab drops whole fields.
  - The ports go first, then the count, then the codec. `one-way` goes last.
  - sipnab never draws part of a number, and the arrowhead always shows.
  - `-` widens the ladder, and `R` hides the detail pane.
- `Enter` on a stream's row opens that stream's **Stream Detail**.
- With the ladder narrowed to one transaction (`f`), sipnab draws no stream
  rows.
- A call with no captured RTP, such as one in a signaling-only capture, gets
  one bar across the ladder instead. It shows the codec the SDP answer
  negotiated.

## Trace a call through proxies (multi-leg)

A call may cross a [B2BUA](glossary.md#b2bua) or [SBC](glossary.md#sbc).

- That is a box that ends the call on one side and starts a new one on the
  other.
- So each side has its own Call-ID, and the call list shows one row per side.

Then press `x` (or `F4`) in the Call Flow to toggle **extended multi-leg
flow**.

- The related legs render together in one ladder.
- So you can follow the call end-to-end through the middle boxes.
- The legs are the ones `--correlate` lists for the call. When the B2BUA
  writes no identifier into the far leg, sipnab ties the legs by their timing
  only, and a busy server can put an unrelated call in the ladder.
  [Follow one call across its legs](follow-a-call.md) shows how to read the tie
  and how to make it exact.
- A leg that stays out of the ladder is not tied to the call. Check with
  `--correlate <CALL-ID>` from the command line.

To put any calls in one ladder yourself, whether sipnab ties them or not, star
each with `Space` in the Call List and press `Enter`. sipnab opens one flow of
all of them, in time order.

## Save what you found

Select the dialogs you want with `Space` in the Call List. Their checkbox
changes from `[ ]` to `[*]`. Then press `F2`.

In the Save dialog, `Tab` cycles the format:

- PCAP,
- PCAP-NG,
- TXT,
- JSON,
- NDJSON,
- CSV,
- **HTML** (a self-contained ladder diagram, drawn with Mermaid, for your
  ticket or wiki),
- Markdown,
- WAV,
- SIPp XML,
- RTP JSON.

`Enter` writes the file. `Shift+Tab` or `Up` / `Down` cycle the same list. With
nothing selected, it saves everything.

**sipnab saves a CSV cell that would start a spreadsheet formula as text.**

- Whoever places the call chooses a From or To user such as `=1+1`.
- sipnab writes it as `"'=1+1"`, so a spreadsheet shows it rather than running it.
- [Keybindings](keybindings.md) lists the characters it guards.

**The HTML diagram draws at most 200 messages.**

- A call with more exports its first 200 as arrows.
- A note inside the diagram names how many messages the call really had.
- The cap exists because the diagram renderer draws nothing at all past 500
  arrows and notes.
- Without the cap, a long call would export as a blank panel with no error.

## Send your notes with the frames they are about

Select the message that matters and press `C`. Type the note and press Enter.

- sipnab shows it in a pane under the flow titled "operator note — not sipnab
  analysis".
- It marks the row with `✎`.
- Press `C` again to amend it, or clear the text to remove it.

To hand the capture over, press `F2`, Tab to PCAP-NG and save.

- Each note is the packet comment on its message's frame. Wireshark shows it.
- The comment has a line naming the frame you typed it on.

To pick the session up later, Tab to NOTES instead. Then start sipnab again with
`--notes` and that file.

- The capture you send carries your notes.
- sipnab never reads them back as analysis.

## Check that it worked

With `sample-call.pcap` open, the first line of the screen names the file and
counts its dialogs, and the Call List has one row for each. This is the top
of a terminal 110 columns wide, from sipnab 0.5.244 on 2026-11-10:

```text
 File: sample-call.pcap    Dialogs: 7 shown of 7    Autoscroll: on
 Capture filter (BPF): none
 View filter: none
  # ▲    Method    From  To     Source             Destination        State      Msgs +Prev    PDD    Duration
> [ ] 1  REGISTER  alice alice  192.0.2.10         192.0.2.20         Registered 4    +0.000s         17ms
  [ ] 2  REGISTER  bob   bob    192.0.2.30         192.0.2.20         Expired    8    +0.500s         14.5s
  [ ] 3  SUBSCRIBE alice alice  192.0.2.10         192.0.2.20         Active     3    +0.700s         30ms
  [ ] 4  SUBSCRIBE bob   bob    192.0.2.30         192.0.2.20         Pending    3    +0.200s         30ms
  [ ] 5  SUBSCRIBE alice alice  192.0.2.10         192.0.2.20         Terminated 6    +0.200s         14.4s
  [ ] 6  OPTIONS   pbx   alice  192.0.2.20         192.0.2.10         Completed  2    +0.400s         6ms
  [ ] 7  INVITE    alice bob    192.0.2.10         192.0.2.20         Completed  7    +3.000s  180ms  8.5s
```

`Dialogs: 7 shown of 7` means no filter hides a call. A lower first number
means a view filter hides the rest: `F9` clears it.

## When something does not work

**`sipnab: the terminal UI could not start: No such device or address (os error 6). It needs a terminal; add -N for a run without one.`**
sipnab started with no terminal on its input, and exited with status 1. Run
it in a terminal, or add `-N` and follow
[Triage a capture from the command line](first-cli-triage.md).

**`-I/--input: 'sample-call.pcap' does not exist`.** The file is not in the
current directory. Download it again with the `curl` command of
[Open a capture](#open-a-capture), or give `-I` its path. From inside the TUI,
`O` opens a file by browsing to it.

**The Call List is empty.** The capture holds no SIP on the ports sipnab reads
by default.
[Read a capture whose SIP is not on port 5060](examples.md#read-a-capture-whose-sip-is-not-on-port-5060)
has the fix.

**A key does something other than this page says.** `F1` lists the keys of
the view you are in, and [Keybindings](keybindings.md) lists every view's.

## Where to go next

- `F1` (or `?`) opens context help in any view. It is the fastest way to see
  what a view can do without leaving it.
- [Keybindings](keybindings.md) -- the complete per-view reference, plus
  an annotated visual tour of every screen.
- [Theme Guide](theme-guide.md) -- recolor the TUI to taste.
- [Cookbook](examples.md) -- the same investigations as one-shot CLI
  commands, for scripting and CI.

<details>
<summary>Why / how we know</summary>

- The 200-message cap is `MAX_MESSAGES` (200) in
  [`src/mermaid.rs`](https://github.com/NormB/sipnab/blob/main/src/mermaid.rs).
- The renderer's limit is `RENDERER_MAX_EDGES` (500) in the same file.
- The vendored Mermaid build refuses a diagram past that many edges outright. It
  does not draw part of it.
- Every arrow and every note is one edge.
- These all draw through that one generator, so they share the cap:
  - the TUI's HTML export,
  - the MCP `render_ladder` tool,
  - the browser analyzer.

</details>
