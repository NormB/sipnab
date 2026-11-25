# Check what a release keeps compatible

This page says which machine-readable outputs of sipnab a program can build
on, which changes to them break such a program, and how to compare two
releases with [`scripts/contract-diff.py`](../scripts/contract-diff.py).

sipnab is at 0.5. Until 1.0, a release may change any surface, and the
[changelog](../CHANGELOG.md) names each change. From 1.0 on, a release that
breaks a surface on this page is a new major version, as
[Semantic Versioning](https://semver.org/) defines it.

## The surfaces the script compares

| Surface | File | Kind |
|---|---|---|
| The REST API under `/v1`: each path, operation, parameter, response status and JSON body | [website/static/openapi.json](../website/static/openapi.json) | `openapi` |
| A call report or full dialog: `--call-report --json` and `GET /v1/dialogs/{id}` | [tests/schemas/call_report.schema.json](../tests/schemas/call_report.schema.json) | `schema` |
| The capture analysis: `--json-analyze`, `GET /v1/report` and the MCP `get_capture_report` answer | [tests/schemas/capture_analysis.schema.json](../tests/schemas/capture_analysis.schema.json) | `schema` |
| One dialog of the `GET /v1/dialogs` list | [tests/schemas/dialog.schema.json](../tests/schemas/dialog.schema.json) | `schema` |
| One SIP message: a `--json` or NDJSON line | [tests/schemas/message.schema.json](../tests/schemas/message.schema.json) | `schema` |
| One line of an operator notes file | [tests/schemas/notes.schema.json](../tests/schemas/notes.schema.json) | `schema` |
| One RTP stream: `GET /v1/streams/{id}` and the `streams` items of a dialog | [tests/schemas/stream.schema.json](../tests/schemas/stream.schema.json) | `schema` |

The script does not yet compare the command line and its exit codes, the
configuration keys, the MCP tools or the Prometheus metric names. The vCon
output follows the IETF vCon draft, and tests/schemas/vcon.schema.json is
that draft's schema, so this page leaves it out.

## Which changes break a program

A change breaks a program when a program written against the older release
can fail against the newer one. Every other change is additive. The script
reads each schema from the side of a reader: a program reads a report, and a
client reads a response.

### A report or a response body

A change is breaking when:

- a property disappears;
- a required property becomes optional, so it may be absent;
- a value may take a type the older release never sent, `null` included;
- a schema drops its `type`, so the value may be of any type;
- a closed list of values (`enum`) gains a value;
- a closed list of values loses its list;
- a fixed value (`const`) changes.

A change is additive when:

- a new property appears, required or not;
- an optional property becomes required;
- a type narrows, as `number` to `integer`;
- a closed list of values loses a value;
- a list marked `"x-sipnab-open-enum": true` in both releases gains a value.

### The REST API operations

A change is breaking when:

- an operation, a method on a path, disappears;
- a parameter disappears;
- a new required parameter appears;
- an optional parameter becomes required;
- a request body becomes required;
- a response status disappears;
- a response's JSON body disappears;
- a response's JSON body changes in a way the rules above call breaking.

A change is additive when:

- a new operation appears;
- a new optional parameter appears;
- a new response status appears;
- a response's JSON body changes in a way the rules above call additive.

### What the script does not compare

The script follows only references inside a document, those that start with
`#/`, and it does not compare:

- descriptions, titles, examples and the `info` object;
- the schema of a request body, and the schema of a parameter;
- a change inside `oneOf`, `anyOf`, `allOf` or `not`;
- bounds, patterns and formats, such as `minimum`, `maxLength`, `pattern` and `format`;
- `additionalProperties`;
- a response body of another media type than `application/json`;
- a JSON body added to a response that had none.

sipnab also reads a notes file back (`--notes`), and the script reads the
notes schema as output only.

## Before you start

- **A clone of the repository with its tags.** A clone made before the newer
  release needs `git fetch --tags`. The script is in the repository from the
  first release after 0.5.268; run it from a clone of `main` or of a later
  release, and name any two release tags.
- **Python 3.** The script uses the standard library only.
- **No change on any other system.** The script reads files of the clone and
  connects to no server, so a running sipnab, its API and the SIP servers
  stay as they are.

```sh
# Run all of these, in order.
git clone https://github.com/NormB/sipnab
cd sipnab
```

## Compare the REST API of two releases

From the top of the clone, write each release's openapi.json to a file,
then compare the files:

```sh
# Run all of these, in order.
git show v0.5.266:website/static/openapi.json > old.json
git show v0.5.267:website/static/openapi.json > new.json
python3 -I scripts/contract-diff.py --kind openapi old.json new.json
```

Between those two releases every change is additive:

```text
additive GET /v1/aggregate query named: parameter added
additive GET /v1/dialogs query named: parameter added
additive GET /v1/dialogs/rates query named: parameter added
additive GET /v1/filters: operation added
additive GET /v1/filters/validate: operation added
additive GET /v1/talkers query named: parameter added
contract-diff: 6 change(s), 0 breaking
```

## Compare a report schema of two releases

Name the file of the schema under tests/schemas/ in both `git show` lines:

```sh
# Run all of these, in order.
git show v0.5.263:tests/schemas/call_report.schema.json > old.json
git show v0.5.264:tests/schemas/call_report.schema.json > new.json
python3 -I scripts/contract-diff.py --kind schema old.json new.json
```

```text
additive $.seen_by: property added
contract-diff: 1 change(s), 0 breaking
```

## Read the result

Each line is one change: `breaking` or `additive`, then where it is, then
what changed. For the REST API, the place is the method and the path, then a
parameter (`query named`) or a response status, then a `$` path into the
JSON body. For a report schema, it is the `$` path alone. A `.name` step
names a property, and `[]` names the items of an array. The last line counts
the changes. The script exits 0 when no change is breaking, 1 when one is,
and 2 when it could not decide.

## Verify the script runs

Compare the work tree's openapi.json with itself. The script prints no
change and exits 0:

```sh
# Run all of these, in order.
python3 -I scripts/contract-diff.py --kind openapi website/static/openapi.json website/static/openapi.json
echo "exit $?"
```

```text
contract-diff: 0 change(s), 0 breaking
exit 0
```

## Troubleshoot

- **Exit 1.** Each `breaking` line names a change that can fail a program
  written against the older release. In a pull request, make the change
  additive: add an optional property or parameter in place of a required
  one, and keep the old property beside a new one.
- **`fatal: invalid object name`.** `git show` found no such tag in the
  clone: run `git fetch --tags`, and check the name with `git tag`.
- **`Expecting value`.** A file is not JSON. When a `git show` line fails,
  its redirection leaves an empty file behind: fix the tag or the path, and
  run that line again.
- **`No such file or directory`.** The script found no file at a path on
  its command line: run it from the top of the clone, or give the full path.
- **`is not local to the document; nothing was decided`.** A `$ref` names
  another file. The script follows only references inside the document.
- **`does not resolve; nothing was decided`.** A `$ref` names a part of the
  document that the document does not hold.
- **``an OpenAPI document has no `paths` object; nothing was decided``.**
  One of the files is not an OpenAPI document, such as a report schema
  given with `--kind openapi`: use `--kind schema` for it.
- **`usage: contract-diff.py --kind schema|openapi OLD.json NEW.json`.** The
  arguments are not the form the usage line shows.
