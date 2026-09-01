#!/usr/bin/env python3
"""Delete the mess a working session leaves behind.

CLAUDE.md has said "delete every temp file in the SAME turn" for months. On
2026-09-01 this checkout held 21 stray `.git/*.log` files written across
sessions, three abandoned worktrees totalling 136 GB, and a 1.6 TB `target/`
-- 44% of a disk that genuinely fills up. The instruction was right and
nothing enforced it, so it was followed exactly as well as an unenforced
instruction ever is.

Wired to a systemd user timer on this box -- `sipnab-clean-stale.timer`,
daily, Persistent -- so it runs whether or not anyone remembers. It is
harmless to run at any moment: see the four safety properties below.

This is the half that reclaims what has already accumulated.
`tests/repo_hygiene_test.rs` is the half that fails while the mess is still
one `rm`, and it drives this script against fixture trees -- a cleaner is the
last thing that should have branches nobody has watched run.

Safe by construction, in this order:

  * DRY RUN by default. It will eventually be run without its flag.
  * An AGE FLOOR. It can run while a build is writing; without a floor that is
    a race rather than a cleanup.
  * A ROOT CHECK. Pointed at the wrong directory, a recursive remover is a
    disaster; it declines rather than doing its best.
  * A CLOSED LIST of suffixes. Never a pattern that could match source.
"""

import argparse
import os
import pathlib
import shutil
import sys
import time

# Logs the hooks write on purpose. CLAUDE.md points at these -- read them
# rather than making a second copy -- so they are a record, not mess.
# `tests/repo_hygiene_test.rs` asserts this prefix appears here, so the gate
# and the cleaner cannot drift into disagreeing about what mess is.
HOOK_LOG_PREFIX = "sipnab-pre-"

# A closed list. Never a glob that could reach a source file: the one mistake
# this tool must not make is unrecoverable, and every other design choice here
# is subordinate to that.
DETRITUS_SUFFIXES = (".orig", ".rej", ".snap.new", ".bak", "~")

# Walked for detritus. `target/` is build output with its own lifecycle and
# millions of files; `.git/` is handled by the log rule alone.
SKIP_DIRS = {".git", "target", "node_modules", ".venv", "website/public"}


def is_checkout(root: pathlib.Path) -> bool:
    """A git checkout, or a worktree whose `.git` is a file pointing at one."""
    return (root / ".git").exists()


def old_enough(path: pathlib.Path, min_age_days: float) -> bool:
    """Older than the floor.

    The floor is what separates a cleaner from a race: this can run while a
    build is writing, and a file touched seconds ago may be in use.
    """
    try:
        age = time.time() - path.stat().st_mtime
    except OSError:
        return False
    return age >= min_age_days * 86_400


def stray_logs(root: pathlib.Path, min_age_days: float) -> list[pathlib.Path]:
    """`.git/*.log` that no hook wrote."""
    gitdir = root / ".git"
    if not gitdir.is_dir():
        return []
    return sorted(
        p
        for p in gitdir.glob("*.log")
        if not p.name.startswith(HOOK_LOG_PREFIX) and old_enough(p, min_age_days)
    )


def detritus(root: pathlib.Path, min_age_days: float) -> list[pathlib.Path]:
    """Conflict and snapshot leftovers, anywhere but the skipped trees."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel = pathlib.Path(dirpath).relative_to(root)
        dirnames[:] = [
            d for d in dirnames if d not in SKIP_DIRS and str(rel / d) not in SKIP_DIRS
        ]
        for name in filenames:
            if name.endswith(DETRITUS_SUFFIXES):
                p = pathlib.Path(dirpath) / name
                if old_enough(p, min_age_days):
                    found.append(p)
    return sorted(found)


def free_gb(root: pathlib.Path) -> float:
    """Free space on the filesystem holding `root`, in GB."""
    st = os.statvfs(root)
    return st.f_bavail * st.f_frsize / 1_000_000_000


def build_caches(root: pathlib.Path) -> list[pathlib.Path]:
    """Regenerable build caches, largest first.

    `incremental/` is a cache cargo rebuilds on demand: removing it costs one
    slower build and nothing else. It reached 551 GB here. Deliberately NOT
    `deps/`, which is 961 GB of the same kind of accumulation but whose partial
    removal leaves cargo rebuilding in confusing ways -- that one is a
    `cargo clean`, which is a decision a person makes, not a cron job.
    """
    out = []
    target = root / "target"
    if not target.is_dir():
        return out
    for child in target.iterdir():
        inc = child / "incremental"
        if inc.is_dir():
            out.append(inc)
    return sorted(out)


def dir_size(path: pathlib.Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(path):
        for name in filenames:
            try:
                total += (pathlib.Path(dirpath) / name).stat().st_size
            except OSError:
                pass
    return total


def size_of(paths) -> int:
    total = 0
    for p in paths:
        try:
            total += p.stat().st_size
        except OSError:
            pass
    return total


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--root", default=str(pathlib.Path(__file__).resolve().parent.parent))
    ap.add_argument(
        "--apply",
        action="store_true",
        help="actually delete; without it nothing is removed and everything "
        "that WOULD be is named",
    )
    ap.add_argument(
        "--reclaim-build-cache",
        action="store_true",
        help="also drop regenerable build caches, but ONLY when free space is "
        "below --disk-floor-gb. Costs one slower build; reclaims hundreds of "
        "GB",
    )
    ap.add_argument(
        "--disk-floor-gb",
        type=float,
        default=250.0,
        help="the pressure threshold for --reclaim-build-cache. Measured "
        "2026-09-01: a full sipnab target/ reached 1.6 TB, of which 551 GB "
        "was incremental cache, on a 3.6 TB disk that was 76%% full",
    )
    ap.add_argument(
        "--min-age-days",
        type=float,
        default=1.0,
        help="leave anything younger alone (default: 1)",
    )
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    if not is_checkout(root):
        print(
            f"{root} is not a git checkout. Refusing: pointed at the wrong "
            f"directory, a recursive remover is a disaster, and doing its "
            f"best is the wrong behavior here.",
            file=sys.stderr,
        )
        return 2

    victims = stray_logs(root, args.min_age_days) + detritus(root, args.min_age_days)
    reclaimed = size_of(victims)

    # Under pressure only. A cache dropped every night is a cache that never
    # pays for itself, so the threshold is what makes this worth wiring to a
    # timer rather than something to run by hand after it hurts.
    if args.reclaim_build_cache:
        free = free_gb(root)
        if free >= args.disk_floor_gb:
            print(
                f"build caches kept: {free:.0f} GB free is above the "
                f"{args.disk_floor_gb:.0f} GB floor"
            )
        else:
            for cache in build_caches(root):
                size = dir_size(cache)
                verb = "removing" if args.apply else "would remove"
                print(f"  {verb} {cache.relative_to(root)} ({size} bytes, regenerable)")
                reclaimed += size
                if args.apply:
                    shutil.rmtree(cache, ignore_errors=True)

    if not victims:
        print(f"nothing stale; removed 0 files, reclaimed {reclaimed} bytes")
        return 0

    verb = "removing" if args.apply else "would remove"
    for p in victims:
        print(f"  {verb} {p.relative_to(root)}")

    if args.apply:
        gone = 0
        for p in victims:
            try:
                p.unlink()
                gone += 1
            except OSError as e:
                print(f"  could not remove {p}: {e}", file=sys.stderr)
        print(f"removed {gone} file(s), reclaimed {reclaimed} bytes")
    else:
        print(
            f"would remove {len(victims)} file(s), reclaiming {reclaimed} "
            f"bytes -- re-run with --apply"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
