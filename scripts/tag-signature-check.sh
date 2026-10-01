#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors
#
# tag-signature-check.sh TAG-SHA
#
# Passes only an ANNOTATED tag carrying a good SSH signature from a key listed
# in the repository's .github/allowed_signers (or $SIPNAB_ALLOWED_SIGNERS, which
# the tests use). A lightweight tag, an unsigned annotated tag, and a tag signed
# by any other key are refused with the reason. .githooks/pre-push runs this on
# every pushed v* tag; tests/tag_signature_gate_test.rs holds it to that.
set -euo pipefail

sha=${1:?usage: tag-signature-check.sh TAG-SHA}
root=$(git rev-parse --show-toplevel 2>/dev/null || pwd)
signers=${SIPNAB_ALLOWED_SIGNERS:-$root/.github/allowed_signers}

case "$(git cat-file -t "$sha" 2>/dev/null)" in
tag) ;;
commit)
	echo "tag ${sha:0:7} is a lightweight tag: it carries no signature. Create it with 'git tag -s'."
	exit 1
	;;
*)
	echo "tag ${sha:0:7}: no such tag object"
	exit 1
	;;
esac

if ! git cat-file -p "$sha" | grep -q -- '-----BEGIN SSH SIGNATURE-----'; then
	echo "tag ${sha:0:7} is not signed. Set 'git config tag.gpgSign true' (SSH signing) and re-create it with 'git tag -s'."
	exit 1
fi

if [ ! -r "$signers" ]; then
	echo "tag ${sha:0:7}: the allowed-signers file $signers is missing, so no signature can be trusted"
	exit 1
fi

# verify-tag exits 1 when the signing key matches no principal in the
# allowed-signers file ("No principal matched"; measured with git 2.43). The
# check also requires the "Good ... signature for <principal>" line, so a
# signature is accepted only when it names a listed signer.
if ! out=$(git -c gpg.format=ssh -c "gpg.ssh.allowedSignersFile=$signers" verify-tag "$sha" 2>&1) \
	|| ! printf '%s\n' "$out" | grep -q '^Good "git" signature for '; then
	echo "tag ${sha:0:7} is signed, but its key is not a trusted signer in $signers:"
	printf '  %s\n' "$out"
	exit 1
fi

echo "tag ${sha:0:7}: $(printf '%s\n' "$out" | grep -m1 'Good')"
