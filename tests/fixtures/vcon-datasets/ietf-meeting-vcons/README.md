# ietf-meeting-vcons

Copied from <https://github.com/vcon-dev/ietf-meeting-vcons> at commit
`b919f24dd29c0419f356c4b1133220c18de3a9ef`, under the BSD 3-Clause License in
[`LICENSE`](LICENSE), copied from the same commit.

| File | Source path | SHA-256 |
|---|---|---|
| `ietf105_iepg_27419.vcon.json` | `ietf105/ietf105_iepg_27419.vcon.json` | `e8b586a4f455302c86d00ebccf83d2f266a4e361e962813237b983491b0c0b32` |
| `ietf108_sec_28277.vcon.json` | `ietf108/ietf108_sec_28277.vcon.json` | `e9c7a54809797d8d17c2998a8b86fab0bcedbe34a3aeba615d2fe99a208e7bbf` |

Both files carry index values that point past the end of an array, which the
schema cannot check: in `ietf105_iepg_27419.vcon.json` the Dialog Object names
parties 0, 1 and 2 and the container has one Party Object; in
`ietf108_sec_28277.vcon.json` each Attachment Object names dialog 0 and the
container has no Dialog Object.
