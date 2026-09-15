"""The test-count claim gate counts what cargo counts.

A ``#[tokio::test]`` is a test cargo runs and the homepage tally reuses cargo's
own "N passed", so a commit message that counts an async test must be checked
against a count that sees it. The gate once counted only ``#[test]`` and read a
commit of three async tests as zero, refusing a true claim. These pin the
counting so that regression cannot return.
"""

import pathlib
import subprocess

REPO = pathlib.Path(__file__).resolve().parent.parent.parent
SCRIPT = REPO / "scripts/check-test-claim.sh"


def net_added(diff: str) -> int:
    out = subprocess.run(
        ["sh", str(SCRIPT), "--net-added"],
        input=diff,
        capture_output=True,
        text=True,
        cwd=REPO,
    )
    assert out.returncode == 0, out.stderr
    return int(out.stdout.strip())


def classify(message: str, actual: int):
    return subprocess.run(
        ["sh", str(SCRIPT), "--classify", str(actual)],
        input=message,
        capture_output=True,
        text=True,
        cwd=REPO,
    )


def test_counts_a_sync_test():
    assert net_added("+    #[test]\n+    fn a() {}\n") == 1


def test_counts_an_async_test():
    # The regression: an async test is a test, and the gate once read it as 0.
    assert net_added("+    #[tokio::test]\n+    async fn a() {}\n") == 1


def test_counts_sync_and_async_together():
    assert net_added("+    #[test]\n+    #[tokio::test]\n") == 2


def test_removed_tests_subtract():
    assert net_added("+    #[test]\n+    #[test]\n-    #[tokio::test]\n") == 1


def test_a_diff_with_no_tests_is_zero():
    assert net_added("+    fn not_a_test() {}\n-    let x = 1;\n") == 0


def test_a_context_line_mentioning_test_is_not_counted():
    # Only added or removed lines count; an unchanged context line that happens
    # to name the attribute must not inflate the total.
    assert net_added("     // see #[tokio::test] above\n+    let x = 1;\n") == 0


def test_classify_agrees_when_the_async_count_matches():
    out = classify("Three tests, mutation-proven: ...\n", 3)
    assert out.returncode == 0, out.stdout
    assert "AGREES" in out.stdout


def test_classify_disagrees_when_the_claim_overcounts():
    out = classify("Four tests, mutation-proven: ...\n", 1)
    assert out.returncode == 1
    assert "DISAGREES" in out.stdout
