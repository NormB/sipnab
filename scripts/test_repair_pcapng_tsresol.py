"""Tests for repair_pcapng_tsresol.py (TDD: written before the implementation).

sipnab <= 0.5.0 wrote pcapng files with nanosecond EPB ticks but no
if_tsresol option in the IDB, so every reader assumed the pcapng default
of microseconds and inflated all times x1000. The repair inserts
if_tsresol=9 into each IDB of sipnab-written sections.
"""

import struct
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "repair_pcapng_tsresol.py"

sys.path.insert(0, str(SCRIPT.parent))
import repair_pcapng_tsresol as repair_mod  # noqa: E402


# ---------------------------------------------------------------- builders

def opt(e, code, val):
    pad = (4 - len(val) % 4) % 4
    return struct.pack(e + "HH", code, len(val)) + val + b"\x00" * pad


def endofopt(e):
    return struct.pack(e + "HH", 0, 0)


def block(e, btype, body):
    total = len(body) + 12
    return (
        struct.pack(e + "II", btype, total)
        + body
        + struct.pack(e + "I", total)
    )


def shb(e, options=b"", section_len=0xFFFFFFFFFFFFFFFF):
    body = struct.pack(e + "IHHQ", 0x1A2B3C4D, 1, 0, section_len) + options
    return block(e, 0x0A0D0D0A, body)


def idb(e, options=b"", linktype=1, snaplen=0xFFFF):
    body = struct.pack(e + "HHI", linktype, 0, snaplen) + options
    return block(e, 0x00000001, body)


def epb(e, payload=b"\xAB" * 64, ts=(0x18C00277, 0xD3D74A30)):
    body = struct.pack(
        e + "IIIII", 0, ts[0], ts[1], len(payload), len(payload)
    ) + payload
    return block(e, 0x00000006, body)


def sipnab_shb(e, **kw):
    return shb(e, options=opt(e, 4, b"sipnab 0.5.0") + endofopt(e), **kw)


def sipnab_idb_opts(e, extra=b""):
    return (
        opt(e, 3, b"sipnab 0.5.0 capture")
        + opt(e, 12, b"linux")
        + extra
        + endofopt(e)
    )


def find_idb_tsresol(e, data, idb_offset):
    """Return the if_tsresol value byte of the IDB at idb_offset, or None."""
    total = struct.unpack_from(e + "I", data, idb_offset + 4)[0]
    opts = data[idb_offset + 16 : idb_offset + total - 4]
    pos = 0
    while pos + 4 <= len(opts):
        code, olen = struct.unpack_from(e + "HH", opts, pos)
        if code == 0:
            break
        if code == 9:
            return opts[pos + 4]
        pos += 4 + ((olen + 3) & ~3)
    return None


# ------------------------------------------------------------- unit tests

class RepairBytesTest(unittest.TestCase):
    def repaired(self, data):
        out, changed, notes = repair_mod.repair(data)
        return out, changed, notes

    def test_inserts_tsresol_when_missing(self):
        e = "<"
        head = sipnab_shb(e)
        tail = epb(e)
        data = head + idb(e, sipnab_idb_opts(e)) + tail
        out, changed, _ = self.repaired(data)
        self.assertTrue(changed)
        self.assertEqual(out[: len(head)], head, "SHB must be untouched")
        self.assertEqual(out[-len(tail):], tail, "EPB bytes must be untouched")
        self.assertEqual(find_idb_tsresol(e, out, len(head)), 9)
        # tsresol option adds exactly 8 bytes to the IDB
        old_total = struct.unpack_from(e + "I", data, len(head) + 4)[0]
        new_total = struct.unpack_from(e + "I", out, len(head) + 4)[0]
        self.assertEqual(new_total, old_total + 8)
        # both length copies must agree
        self.assertEqual(
            struct.unpack_from(e + "I", out, len(head) + new_total - 4)[0],
            new_total,
        )

    def test_idempotent(self):
        e = "<"
        data = sipnab_shb(e) + idb(e, sipnab_idb_opts(e)) + epb(e)
        once, changed, _ = self.repaired(data)
        self.assertTrue(changed)
        twice, changed_again, _ = self.repaired(once)
        self.assertFalse(changed_again)
        self.assertEqual(once, twice)

    def test_existing_correct_tsresol_untouched(self):
        e = "<"
        data = sipnab_shb(e) + idb(
            e, sipnab_idb_opts(e, extra=opt(e, 9, b"\x09"))
        )
        out, changed, _ = self.repaired(data)
        self.assertFalse(changed)
        self.assertEqual(out, data)

    def test_existing_other_tsresol_left_alone_with_note(self):
        e = "<"
        data = sipnab_shb(e) + idb(
            e, sipnab_idb_opts(e, extra=opt(e, 9, b"\x06"))
        )
        out, changed, notes = self.repaired(data)
        self.assertFalse(changed)
        self.assertEqual(out, data)
        self.assertTrue(any("tsresol" in n for n in notes))

    def test_idb_with_no_options_at_all(self):
        e = "<"
        head = sipnab_shb(e)
        data = head + idb(e, b"") + epb(e)
        out, changed, _ = self.repaired(data)
        self.assertTrue(changed)
        self.assertEqual(find_idb_tsresol(e, out, len(head)), 9)
        # tsresol option (8) + newly required opt_endofopt (4)
        new_total = struct.unpack_from(e + "I", out, len(head) + 4)[0]
        self.assertEqual(new_total, 20 + 12)

    def test_big_endian_section(self):
        e = ">"
        head = sipnab_shb(e)
        data = head + idb(e, sipnab_idb_opts(e)) + epb(e)
        out, changed, _ = self.repaired(data)
        self.assertTrue(changed)
        self.assertEqual(find_idb_tsresol(e, out, len(head)), 9)

    def test_multiple_idbs_repaired(self):
        e = "<"
        head = sipnab_shb(e)
        first = idb(e, sipnab_idb_opts(e))
        data = head + first + idb(e, sipnab_idb_opts(e)) + epb(e)
        out, changed, _ = self.repaired(data)
        self.assertTrue(changed)
        self.assertEqual(find_idb_tsresol(e, out, len(head)), 9)
        second_off = len(head) + len(first) + 8
        self.assertEqual(find_idb_tsresol(e, out, second_off), 9)

    def test_explicit_section_length_adjusted(self):
        e = "<"
        body = idb(e, sipnab_idb_opts(e)) + epb(e)
        head = sipnab_shb(e, section_len=len(body))
        out, changed, _ = self.repaired(head + body)
        self.assertTrue(changed)
        got = struct.unpack_from(e + "Q", out, 16)[0]
        self.assertEqual(got, len(body) + 8)

    def test_multiple_sections_mixed_endianness(self):
        le = sipnab_shb("<") + idb("<", sipnab_idb_opts("<"))
        be = sipnab_shb(">") + idb(">", sipnab_idb_opts(">"))
        out, changed, _ = self.repaired(le + be)
        self.assertTrue(changed)
        self.assertEqual(find_idb_tsresol("<", out, len(sipnab_shb("<"))), 9)
        be_idb_off = len(le) + 8 + len(sipnab_shb(">"))
        self.assertEqual(find_idb_tsresol(">", out, be_idb_off), 9)

    def test_non_sipnab_file_skipped(self):
        # a generic capture without tsresol is legitimately microseconds
        e = "<"
        data = shb(e, options=opt(e, 4, b"tcpdump") + endofopt(e)) + idb(
            e, opt(e, 3, b"eth0 capture") + endofopt(e)
        )
        out, changed, notes = self.repaired(data)
        self.assertFalse(changed)
        self.assertEqual(out, data)
        self.assertTrue(any("sipnab" in n for n in notes))

    def test_force_repairs_non_sipnab_file(self):
        e = "<"
        data = shb(e) + idb(e, endofopt(e))
        out, changed, _ = repair_mod.repair(data, force=True)
        self.assertTrue(changed)
        self.assertEqual(find_idb_tsresol(e, out, len(shb(e))), 9)

    # ----------------------------------------------------- adversarial

    def test_empty_file_rejected(self):
        with self.assertRaises(ValueError):
            repair_mod.repair(b"")

    def test_garbage_rejected(self):
        with self.assertRaises(ValueError):
            repair_mod.repair(b"\x00\x01\x02\x03" * 16)

    def test_pcap_classic_rejected(self):
        with self.assertRaises(ValueError):
            repair_mod.repair(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))

    def test_truncated_block_rejected(self):
        e = "<"
        data = sipnab_shb(e) + idb(e, sipnab_idb_opts(e))
        with self.assertRaises(ValueError):
            repair_mod.repair(data[:-6])

    def test_inconsistent_trailing_length_rejected(self):
        e = "<"
        bad = bytearray(sipnab_shb(e) + idb(e, sipnab_idb_opts(e)))
        bad[-4:] = struct.pack(e + "I", 8)
        with self.assertRaises(ValueError):
            repair_mod.repair(bytes(bad))

    def test_option_length_overrunning_block_rejected(self):
        e = "<"
        overrun = struct.pack(e + "HH", 3, 60000)  # claims 60000-byte value
        with self.assertRaises(ValueError):
            repair_mod.repair(sipnab_shb(e) + idb(e, overrun))

    def test_option_value_with_nul_and_backslashes_ok(self):
        e = "<"
        weird = opt(e, 3, b"sipnab\x00\\weird\\\x00")
        head = sipnab_shb(e)
        data = head + idb(e, weird + endofopt(e))
        out, changed, _ = self.repaired(data)
        self.assertTrue(changed)
        self.assertEqual(find_idb_tsresol(e, out, len(head)), 9)


# -------------------------------------------------------------- CLI tests

class CliTest(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.dir = tempfile.TemporaryDirectory()
        self.path = Path(self.dir.name) / "cap.pcapng"
        e = "<"
        self.original = sipnab_shb(e) + idb(e, sipnab_idb_opts(e)) + epb(e)
        self.path.write_bytes(self.original)

    def tearDown(self):
        self.dir.cleanup()

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
        )

    def test_repairs_in_place_with_backup(self):
        r = self.run_cli(str(self.path))
        self.assertEqual(r.returncode, 0, r.stderr)
        bak = self.path.with_suffix(self.path.suffix + ".bak")
        self.assertEqual(bak.read_bytes(), self.original)
        repaired = self.path.read_bytes()
        self.assertNotEqual(repaired, self.original)
        self.assertEqual(find_idb_tsresol("<", repaired, 32), 9)

    def test_second_run_is_noop_and_keeps_backup(self):
        self.run_cli(str(self.path))
        bak = self.path.with_suffix(self.path.suffix + ".bak")
        repaired = self.path.read_bytes()
        r = self.run_cli(str(self.path))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.path.read_bytes(), repaired)
        self.assertEqual(bak.read_bytes(), self.original)

    def test_dry_run_touches_nothing(self):
        r = self.run_cli("--dry-run", str(self.path))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.path.read_bytes(), self.original)
        self.assertFalse(
            self.path.with_suffix(self.path.suffix + ".bak").exists()
        )
        self.assertIn("would repair", r.stdout)

    def test_refuses_to_clobber_existing_backup(self):
        bak = self.path.with_suffix(self.path.suffix + ".bak")
        bak.write_bytes(b"precious")
        r = self.run_cli(str(self.path))
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(bak.read_bytes(), b"precious")
        self.assertEqual(self.path.read_bytes(), self.original)

    def test_garbage_file_errors_and_is_untouched(self):
        junk = Path(self.dir.name) / "junk.pcapng"
        junk.write_bytes(b"not a pcapng at all")
        r = self.run_cli(str(junk))
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(junk.read_bytes(), b"not a pcapng at all")

    def test_missing_file_errors(self):
        r = self.run_cli(str(Path(self.dir.name) / "nope.pcapng"))
        self.assertNotEqual(r.returncode, 0)


if __name__ == "__main__":
    unittest.main()
