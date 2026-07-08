#!/usr/bin/env python3
"""Repair pcapng files written by sipnab <= 0.5.0.

Those files store EPB timestamps as NANOSECOND ticks but carry no
if_tsresol option in the Interface Description Block, so readers assume
the pcapng default of microseconds and inflate every time value x1000
(42 ms PDD shown as 41972 ms, capinfos reporting year 58484).

The repair inserts an ``if_tsresol = 9`` option into each IDB. Packet
data and timestamps are byte-for-byte untouched; only the interface's
declared resolution changes, which is how the stored ticks were always
meant to be read.

Safety: a pcapng without if_tsresol is normally a legitimate
microsecond-resolution file, so by default only sections that identify
themselves as sipnab-written (shb_userappl or if_description containing
"sipnab") are repaired; anything else is skipped with a note. Use
--force to override. In-place repair keeps the original as <file>.bak.
"""

import argparse
import os
import struct
import sys
import tempfile

SHB_TYPE = 0x0A0D0D0A
IDB_TYPE = 0x00000001
BYTE_ORDER_MAGIC = 0x1A2B3C4D
UNSPECIFIED_SECTION_LEN = 0xFFFFFFFFFFFFFFFF

OPT_ENDOFOPT = 0
OPT_IF_DESCRIPTION = 3
OPT_SHB_USERAPPL = 4
OPT_IF_TSRESOL = 9


def _options(e, area):
    """Parse an option area into (code, value, raw_start, raw_end) tuples."""
    out = []
    pos = 0
    while pos < len(area):
        if pos + 4 > len(area):
            raise ValueError("option header runs past the option area")
        code, olen = struct.unpack_from(e + "HH", area, pos)
        end = pos + 4 + ((olen + 3) & ~3)
        if pos + 4 + olen > len(area) or end > len(area):
            raise ValueError("option value runs past the option area")
        out.append((code, area[pos + 4 : pos + 4 + olen], pos, end))
        pos = end
        if code == OPT_ENDOFOPT:
            break
    return out


def _tsresol_option(e):
    return struct.pack(e + "HH", OPT_IF_TSRESOL, 1) + b"\x09\x00\x00\x00"


def _endofopt(e):
    return struct.pack(e + "HH", OPT_ENDOFOPT, 0)


def _repair_idb(e, block_body, notes, label):
    """Return (new_body, changed) for an IDB body (without type/lengths)."""
    if len(block_body) < 8:
        raise ValueError("IDB body shorter than its fixed fields")
    fixed, area = block_body[:8], block_body[8:]
    opts = _options(e, area)
    for code, value, _, _ in opts:
        if code == OPT_IF_TSRESOL:
            resol = value[0] if value else None
            if resol != 9:
                notes.append(
                    f"{label}: existing if_tsresol={resol!r} is not the "
                    "sipnab bug signature; left alone"
                )
            return block_body, False
    endofopt_at = next(
        (start for code, _, start, _ in opts if code == OPT_ENDOFOPT), None
    )
    if endofopt_at is None:
        new_area = area + _tsresol_option(e) + _endofopt(e)
    else:
        new_area = area[:endofopt_at] + _tsresol_option(e) + area[endofopt_at:]
    return fixed + new_area, True


def repair(data, force=False):
    """Repair pcapng bytes; return (out_bytes, changed, notes)."""
    if len(data) < 28:
        raise ValueError("too short to be a pcapng file")
    if data[:4] != struct.pack(">I", SHB_TYPE):
        raise ValueError("not a pcapng file (no Section Header Block)")

    out = bytearray()
    notes = []
    pos = 0
    endian = None
    # (offset of section_length field in `out`, declared length, delta)
    section = None
    idb_index = 0

    def flush_section():
        if section is None:
            return
        off, declared, delta = section
        if declared != UNSPECIFIED_SECTION_LEN and delta:
            out[off : off + 8] = struct.pack(endian + "Q", declared + delta)

    while pos < len(data):
        if pos + 8 > len(data):
            raise ValueError(f"truncated block header at offset {pos}")
        raw_type = data[pos : pos + 4]
        if raw_type == struct.pack(">I", SHB_TYPE):
            if pos + 16 > len(data):
                raise ValueError("truncated Section Header Block")
            magic = struct.unpack_from("<I", data, pos + 8)[0]
            if magic == BYTE_ORDER_MAGIC:
                new_endian = "<"
            elif struct.unpack_from(">I", data, pos + 8)[0] == BYTE_ORDER_MAGIC:
                new_endian = ">"
            else:
                raise ValueError("bad byte-order magic in Section Header Block")
            flush_section()
            endian = new_endian
        elif endian is None:
            raise ValueError("file does not start with a Section Header Block")

        btype, total = struct.unpack_from(endian + "II", data, pos)
        if total < 12 or total % 4 != 0:
            raise ValueError(f"bad block length {total} at offset {pos}")
        if pos + total > len(data):
            raise ValueError(f"block at offset {pos} runs past end of file")
        trailer = struct.unpack_from(endian + "I", data, pos + total - 4)[0]
        if trailer != total:
            raise ValueError(
                f"block at offset {pos}: leading/trailing lengths disagree "
                f"({total} != {trailer})"
            )
        body = data[pos + 8 : pos + total - 4]

        if btype == SHB_TYPE:
            declared = struct.unpack_from(endian + "Q", body, 8)[0]
            shb_opts = _options(endian, body[16:])
            userappl = next(
                (v for c, v, _, _ in shb_opts if c == OPT_SHB_USERAPPL), b""
            )
            section_is_sipnab = b"sipnab" in userappl
            section = (len(out) + 16, declared, 0)
            out += data[pos : pos + total]
        elif btype == IDB_TYPE:
            idb_index += 1
            label = f"IDB #{idb_index}"
            idb_opts = _options(endian, body[8:])
            descr = next(
                (v for c, v, _, _ in idb_opts if c == OPT_IF_DESCRIPTION), b""
            )
            eligible = force or section_is_sipnab or b"sipnab" in descr
            if not eligible:
                has_tsresol = any(
                    c == OPT_IF_TSRESOL for c, _, _, _ in idb_opts
                )
                if not has_tsresol:
                    notes.append(
                        f"{label}: no if_tsresol but the section does not "
                        "identify as sipnab-written; skipped (use --force)"
                    )
                out += data[pos : pos + total]
            else:
                new_body, changed = _repair_idb(endian, body, notes, label)
                if changed:
                    new_total = len(new_body) + 12
                    out += struct.pack(endian + "II", btype, new_total)
                    out += new_body
                    out += struct.pack(endian + "I", new_total)
                    off, declared, delta = section
                    section = (off, declared, delta + (new_total - total))
                    notes.append(f"{label}: inserted if_tsresol=9")
                else:
                    out += data[pos : pos + total]
        else:
            out += data[pos : pos + total]

        pos += total

    flush_section()
    result = bytes(out)
    return result, result != data, notes


def _repair_file(path, dry_run, force, no_backup):
    with open(path, "rb") as f:
        data = f.read()
    fixed, changed, notes = repair(data, force=force)
    for note in notes:
        print(f"{path}: {note}")
    if not changed:
        print(f"{path}: already correct, nothing to do")
        return
    if dry_run:
        print(f"{path}: would repair ({len(fixed) - len(data):+d} bytes)")
        return
    if not no_backup:
        bak = path + ".bak"
        if os.path.exists(bak):
            raise FileExistsError(
                f"{bak} already exists; move it aside or pass --no-backup"
            )
        os.replace(path, bak)
        src_stat = os.stat(bak)
    else:
        src_stat = os.stat(path)
    fd, tmp = tempfile.mkstemp(
        dir=os.path.dirname(os.path.abspath(path)), suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(fixed)
        os.chmod(tmp, src_stat.st_mode & 0o7777)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    print(f"{path}: repaired ({len(fixed) - len(data):+d} bytes)")


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("files", nargs="+", help="pcapng files to repair in place")
    ap.add_argument(
        "--dry-run", action="store_true", help="report only, change nothing"
    )
    ap.add_argument(
        "--force",
        action="store_true",
        help="repair even if the file does not identify as sipnab-written",
    )
    ap.add_argument(
        "--no-backup",
        action="store_true",
        help="do not keep the original as <file>.bak",
    )
    args = ap.parse_args(argv)

    status = 0
    for path in args.files:
        try:
            _repair_file(path, args.dry_run, args.force, args.no_backup)
        except (OSError, ValueError) as exc:
            print(f"{path}: error: {exc}", file=sys.stderr)
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
