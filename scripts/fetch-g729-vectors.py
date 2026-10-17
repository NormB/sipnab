#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Fetch the ITU-T G.729 and G.729.1 decoder test vectors.

The vectors ship inside the ITU-T G.729 (06/2012) Release 3 software package,
which also holds the reference C code. The clean-room build of crates/g729
must never see that code, so this script extracts ONLY the entries under

    Software/G729_Release3/g729AnnexA/test_vectors/
    Software/G729_Release3/g729AnnexB/test_vectors/

plus the sixteen source files named in SOURCES, each by path and pinned
sha256, and never lists, prints or opens any other entry. The sources are the
input of the sipnab-g729 crate's table importer (`g729::import_from_itu`): the
trained codebooks are user-supplied and never committed, so the conformance
tests build their tables from these files. Nothing here reads those files
beyond hashing them. The vectors and sources are fetched, never committed
(spec decision D4).

The G.729.1 core-layer tests read seven bitstreams of a second package, the
ITU-T G.729.1 (2006) Corrigendum 1 (08/2009) software package: G.729.1
bitstreams and the G.729-format bitstreams encoded from the same inputs. This
script extracts ONLY those seven entries, each by path and pinned sha256,
from

    Software/G.729.1_V1.5_Part3_dtxcng_fixed-point_AnnexC/test_vectors_Annex_C_090727/

and never lists, prints or opens any other entry of that package.

What a fetch guarantees:

* The package is the pinned one: its size and sha256 are checked before any
  entry is read. A package with another hash is refused and deleted.
* Every extracted file is checked against its own pinned sha256, and a
  pinned file missing from the package is an error.
* The downloaded package is deleted once the vectors are extracted.

Usage:
    fetch-g729-vectors.py [--zip FILE] [--g7291-zip FILE] [--g7291-only] [DEST]

DEST defaults to $G729_VECTORS, else crates/g729/test-vectors (gitignored).
The Annex A vectors land in DEST/annex-a, the Annex B ones in DEST/annex-b,
the sources in DEST/itu-source/<path below Software/G729_Release3/>, and the
G.729.1 vectors in DEST/g7291. With --zip or --g7291-zip, a local copy of
that package is used instead of downloading, and it is left in place. With
--g7291-only, only the G.729.1 package is fetched. Exit codes: 0 fetched and
verified, 1 failed.
"""

import argparse
import hashlib
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request
import zipfile

PACKAGE_URL = (
    "https://www.itu.int/rec/dologin_pub.asp?lang=e"
    "&id=T-REC-G.729-201206-I!!SOFT-ZST-E&type=items"
)
PACKAGE_SIZE = 18_476_968
PACKAGE_SHA256 = "979680ff3b52b13a5701453178efd32b53e340114638fd330fdb6669eec86620"

ENV_VAR = "G729_VECTORS"
DEFAULT_DEST = pathlib.Path(__file__).resolve().parent.parent / "crates/g729/test-vectors"

A = "Software/G729_Release3/g729AnnexA/test_vectors/"
B = "Software/G729_Release3/g729AnnexB/test_vectors/"
SRC = "Software/G729_Release3/"
SUBDIR = {A: "annex-a", B: "annex-b"}

# sha256 of every file in the two test_vectors directories of the pinned package.
PINS = {
    A + "ALGTHM.BIT": "1d0aa1048aee99809d34ed0a5e6763549523c7496cf8945035259544a41343ed",
    A + "ALGTHM.IN": "cd97c420c7ba923fac59491e90db2c9009210261142052b58352a6a1b894d293",
    A + "ALGTHM.PST": "886cdf3fa778f14006a2aa6c8b180446d834121d74d4b7968eb078d48f586d57",
    A + "ERASURE.BIT": "856934c7ca84317822e6b3d789012bda7eab03daf89a3c03b269e705efa60fc4",
    A + "ERASURE.PST": "3314661a641be8d627d561eb29b3172718c572c02a49a9e96a0d796aa60d0fce",
    A + "FIXED.BIT": "cfbd4be26ad6b764c7526a53c2153b9f302909f97f219dc1c7eaf38d7d447315",
    A + "FIXED.IN": "577f3a6ce0a92f021e80f340272fd812fc2c39d0ee7119cde348f961a9a91773",
    A + "FIXED.PST": "1e94496c36399e527ba9263c82e0d13c1ccaf8d57d66a5eb7300513ba2e8376d",
    A + "LSP.BIT": "9be5995a67e9b9a9a9161a51cc435e70cc81442f5eb1f2d5e14decfd0bd8554e",
    A + "LSP.IN": "859cf4924c409e5f2426a0bc38b2fa3cd9af92804e5cb05138436e7fd1d9822a",
    A + "LSP.PST": "e2e41a50e71a69d92366a4fb922477dfdff865aa54dc29039bd7093c7825f979",
    A + "OVERFLOW.BIT": "6c8b21ac404975f2dadd41184102a77ae0a1595be5946ed419ce3a2136bf3e9b",
    A + "OVERFLOW.PST": "96ebe18718c3a4254a80628a35583a0207d0023de74b7b9b80ba7b37d5834cb6",
    A + "PARITY.BIT": "9841a71a32b60a36e46b7e878f817b8c4f365908981bb77fde3d2787b7834839",
    A + "PARITY.PST": "a0c1319bdf5b45d30a4cc708c6b2de0e2491cb3a70b21afa98593d6d1915eeda",
    A + "PITCH.BIT": "25a542312e6ca2935afc9f552a165fa0a5a0bc161a2b3af68245f5bbe42fa821",
    A + "PITCH.IN": "96da3878350cb586699ac11653c6cbe5947f39aa6a75c012981d44118a848de5",
    A + "PITCH.PST": "51d5080e49886a79ebaad7f286cc3e48713d3e0c0bb803b45b05e7f642d90507",
    A + "READMETV.txt": "a502368ff011a51096856b05c7e1d7ccad5204d4fe8958c012ea4e88fda5d54e",
    A + "SPEECH.BIT": "52c3d0050a8467cc1727fb3d8d12328c16a5aa47d4d298ce927946258b3f26cc",
    A + "SPEECH.IN": "0fceb7702a05d09a9a39d5442c56b827ae0f43eb88a33746ab6f28e7ab5849d5",
    A + "SPEECH.PST": "d9efc1e250628d59bd8874af5b64f0a0bf2c238a818e70f9adf2c0d6c78a8da3",
    A + "TAME.BIT": "b8cc727ebb8ff75c4593b523f04ab1b233566674663263ca4363106d860de771",
    A + "TAME.IN": "5039e601bda42f3e91b6e9447b3ad8a052df8d2ef941d202926ee97edba51ea8",
    A + "TAME.PST": "197cf0d5b1ca5abd14a8bd28b02113bbdcdbc21f2870283d1ae51ee7b3d8da48",
    A + "TEST.BAT": "325fc498d399b617168ce173e0b27d3a7c5615f0cbf221dcce7f58b93168520f",
    A + "TEST.BIT": "c35e0f274ee22ea5b03ba9006a3e2e485c06fb54172ce480bedafd5207d64d5a",
    A + "TEST.IN": "5df4fc223c4887eeb7a921b451dc197e7f6c3ae5750b0fe2c5927ca22d6960ee",
    A + "TEST.pst": "b2aef0eb454aa36c746a58f6e533b74548b305a3223a0a863e4ac43c5a27bf93",
    B + "readmeabTV.txt": "c8f9de17cfc1bc36b8730114b85022ebf49195a338c9a204f9ddb9cf2c2feae8",
    B + "readmebTV.txt": "0891881ed43b14d3a34faac1af9198d6f86097a2470b544ad4725a2453df5bfd",
    B + "test_ab.bat": "41c48d869b3c86ff167170455824c820b60acdc113f120e0cf3fed85b778f5e9",
    B + "test_b.bat": "47bc01ed926f733af2202b1af2c86c83d997d58a0caf2db468ff8f8e98830c64",
    B + "tstseq1.bin": "4d4cff3547d8a4931b78af999dcc09f19c98f027371ea60b0853ad647b8fbc55",
    B + "tstseq1.bit": "eefa6358eb7891ac9d6a5f6842265c19c7a56f586f6aee3564929bcb5197a98b",
    B + "tstseq1.out": "4d5ba40fb6ba08de3431937d296c5f2fcba9fe18b1394c4448d4772b6c0f35d6",
    B + "tstseq1a.bit": "f35810d05602199f08920e09d0b9d1250a6ee2e81efda528bc99cbc18e3061ec",
    B + "tstseq1a.out": "84e3a7a19896f55b27dca60e948cbbb49ee74032e5b7ddabc9774c0dbe2bb93b",
    B + "tstseq2.bin": "d832c151a0fd3892996f86672409507f7eab624b77b630960fb63f2196480650",
    B + "tstseq2.bit": "ff2d0ac7f98e3fe147209b25d82cf73fbd242dcbf92fd463673d168e4e9ecf02",
    B + "tstseq2.out": "bb9f2ca12a6a32116071d21fc66126d454ee80dba15bab35a684b21c6ec598ae",
    B + "tstseq2a.bit": "3ad9c2c503e359ccf3e0d07d5bf03007b5de0f58f10c636be1d450c0badb6e09",
    B + "tstseq2a.out": "8d098f50226e9e07a660f9b8ab5cae6f008d022dce1ea8a8ca70b1a9af6f43c5",
    B + "tstseq3.bin": "92ff51ef9dd9df82b5d873041d444394b600ca6b9feddbe33ebc6415a40bc9c6",
    B + "tstseq3.bit": "11b33cb319d61c39b7f967ff1296a1ad62eac2a6b245d900f5ae2105be59363b",
    B + "tstseq3.out": "5b0fded37fd68a5c5256995e87079f7a82cd970b3a8752b7441ba82b0ab5e11b",
    B + "tstseq3a.bit": "a93a3a80c5f238e0a039eccfc1f9dd1c78a90076b208983f453f505fd18598b1",
    B + "tstseq3a.out": "04e62a7ad033fd12d1e00cf8de13383875faf4b764673d49fd87a45070d687db",
    B + "tstseq4.bin": "777a2b434fd949b387553174c4d6e5dc3ae16125ed64efb9b82b3f443d078de0",
    B + "tstseq4.bit": "166645af51b5e713dba15a30d21d822ed65d9346f220efe072834f8253da2f2b",
    B + "tstseq4.out": "5ef6c8b9cf59b341ca98b3608709fff665a05f81d986b7f2d3776a5e373f59b5",
    B + "tstseq4a.bit": "d9ed1bb63a5cdbed5d10b95b58f4c2c4b22546872174d728eab1402e8eb61bfd",
    B + "tstseq4a.out": "792ba836445c75d1c2b90e40bbf9e4f3f16561f464f8cae1fd1bf45182dd1cd2",
    B + "tstseq5.bit": "20321301a3e9a0fa30e950b5f287db7d79b573d234b434945cae8dcc25d83a7a",
    B + "tstseq5.out": "c5c69d81306863d8b0875a599a9ce3e87ce8c84ca703c7b0dae249da581af337",
    B + "tstseq5a.out": "733a12c69c6b9c9161846cfd556ba329a95f2ad357127952aca45e2ad7f4acb4",
    B + "tstseq6.bit": "55dc024e7329324a4fd0e230d91d9d0cd022c031ef159dede0aad29e7c958fef",
    B + "tstseq6.out": "6e68966473cba256886c69a7b6ee66585b21d53d7f1d64717dfb377805f660c7",
    B + "tstseq6a.out": "cacb86ed7e8fef9f0111ca7356a77b6e72aed7dbcb7df079ef602b1e602a5892",
}


# sha256 of each source file the table importer reads. The hashes are those
# recorded by the oracle in its table extraction (one per source file).
SOURCES = {
    SRC + "g729AnnexA/c_code/TAB_LD8A.C": "deefd5e1b7d02d6994cdbc65491d9eafe40fe52e5291eaaf26848cd2132fe5a1",
    SRC + "g729AnnexB/c_codeBA/tab_ld8a.c": "d2e9271cd7e1931fe1fabe3029881f6fbf83576e9360c9b2bd6a2fffdd9e6226",
    SRC + "g729AnnexA/c_code/DEC_LD8A.C": "981d1047fb350b46f391bc1585df50cd4f7c3da216e9789efcbaf303eb594f5c",
    SRC + "g729AnnexA/c_code/DEC_GAIN.C": "07fb8695db5d46e76af9cf6e8c23faa5c3ca26bff202ba36db806b6e8fb2932c",
    SRC + "g729AnnexB/c_codeBA/dec_sid.c": "951942993deb24afdcd82f7a4265f7072b3b4cf8b768a20b404fe0dd64f11f1d",
    SRC + "g729AnnexB/c_codeBA/tab_dtx.c": "165ed446bc179aaad30673aa8390139bdfab13f7ea6e0322285f14d0320ba325",
    SRC + "g729AnnexA/c_code/LD8A.H": "e53cb6066d554792260ad7b19756e01dda035a0ca1dd266c23d25a199e8ca43c",
    SRC + "g729AnnexA/c_code/DE_ACELP.C": "1e517c5cf1fb3cb6ea9330edd911482f7fe146dfa5d72da9a781ec35e3664f5d",
    SRC + "g729AnnexA/c_code/GAINPRED.C": "c9f9a64d895a2212f4b59adda2db6063d54bea766671df32b53960da60d2a426",
    SRC + "g729AnnexA/c_code/UTIL.C": "8f0bd79ab8807ad1d5b350c0ec3a1cf9423dcf7abc4a74d5a9e165d591564fc5",
    SRC + "g729AnnexA/c_code/LPCFUNC.C": "e87de93a75c715507bd26c5a6cc76a6a06efd6149e34fd422c382ae1911fe80d",
    SRC + "g729AnnexA/c_code/POSTFILT.C": "5cb46384777ddac5764684790f4578632eabcf0085c5094750b635fa179cd614",
    SRC + "g729AnnexB/c_codeBA/dtx.h": "1abf6fd06e46e1d25e55b39dce27d3704b711d563f9f618a3c3287706116d352",
    SRC + "g729AnnexB/c_codeBA/octet.h": "813afebb43e88174e1c6a9669136d8782f804b3867b9e6fb5251ba0a7f865941",
    SRC + "g729AnnexB/c_codeBA/calcexc.c": "997fc1954fadf89a4e6aab181456144f54a0b37d55202d6f39308eef8dbf988d",
    SRC + "g729AnnexB/c_codeBA/qsidgain.c": "931663dd17a7095233bb9c4e0b3d54bac9ed5c3aa5575bbcfc501494e7909eb7",
}

ALL_PINS = {**PINS, **SOURCES}

G7291_PACKAGE_URL = (
    "https://www.itu.int/rec/dologin_pub.asp?lang=e"
    "&id=T-REC-G.729.1-200908-I!Cor1!SOFT-ZST-E&type=items"
)
G7291_PACKAGE_SIZE = 9_217_472
G7291_PACKAGE_SHA256 = "6fe1c9db88a6cc3431ae97450e7811536b25afeb66477254e757763c43642675"

C = "Software/G.729.1_V1.5_Part3_dtxcng_fixed-point_AnnexC/test_vectors_Annex_C_090727/"
SUBDIR[C] = "g7291"

# sha256 of each G.729.1 vector the core-layer tests read. test1_16k.b32 is a
# 32 kbit/s G.729.1 bitstream and test1_16k.b8 the G.729-format bitstream of
# the same input; test2_8k.* and test3_16k.* are the same with discontinuous
# transmission (SID frames).
G7291_PINS = {
    C + "test1_16k.b32": "bf407d7b33f1106bd8b91635854861927ed1e8e21d001cd76a5803318ff6199f",
    C + "test1_16k.b8": "e1344bad777465358ab060054d29581ed5641bd34306af327af0e615d77cd4fb",
    C + "test2_8k.b8": "a56f3323d5fc845b89da30f2e22b930fac36174bd3841646a5140436c26c40f1",
    C + "test2_8k.b12": "4f8aeaeea112d8e61f87b397c2c1d3305c08c01205754fb97a5120620f5273ab",
    C + "test2_8k.b729b": "6e00f816f4f0c4b98c422a32d624eba424d9d4e37d76f3eab3cdfcf94e68e6ba",
    C + "test3_16k.b32": "e3c1d5a9023fe687a9a9107390342d23cee344fee9201d131c552cfe21025e2e",
    C + "test3_16k.b729b": "0fada1ac457e89fcb2eaeafce4393b434d33cad905bd80c0d180368c320939b0",
}


class FetchError(Exception):
    """The package or one of its vectors could not be fetched or verified."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_package(path, expected_size=PACKAGE_SIZE, expected_sha256=PACKAGE_SHA256):
    """Refuse a package whose size or sha256 is not the pinned one."""
    size = os.path.getsize(path)
    actual = sha256_file(path)
    if size != expected_size or actual != expected_sha256:
        raise FetchError(
            f"package sha256 mismatch: expected {expected_sha256} "
            f"({expected_size} bytes), got {actual} ({size} bytes)"
        )


def destination(dest, entry):
    """Where a pinned entry is written: DEST/annex-a/NAME or DEST/annex-b/NAME."""
    for prefix, subdir in SUBDIR.items():
        if entry.startswith(prefix):
            return pathlib.Path(dest) / subdir / entry[len(prefix):]
    if entry.startswith(SRC) and "/test_vectors/" not in entry:
        return pathlib.Path(dest) / "itu-source" / entry[len(SRC):]
    raise FetchError(f"not a test-vector or pinned source entry: {entry}")


def extract(package, dest, pins=None):
    """Extract the pinned test-vector and source entries of `package` into `dest`.

    Only names that are keys of `pins` are read; every other entry of the
    archive is never opened. Each file is written under a temporary name,
    checked against its pin, and renamed into place only when it matches.
    """
    pins = ALL_PINS if pins is None else pins
    with zipfile.ZipFile(package) as archive:
        present = {info.filename for info in archive.infolist() if info.filename in pins}
        missing = sorted(set(pins) - present)
        if missing:
            raise FetchError("package lacks pinned files: " + ", ".join(missing))
        for entry, expected in sorted(pins.items()):
            target = destination(dest, entry)
            target.parent.mkdir(parents=True, exist_ok=True)
            data = archive.read(entry)
            actual = hashlib.sha256(data).hexdigest()
            if actual != expected:
                raise FetchError(
                    f"{entry}: sha256 mismatch: expected {expected}, got {actual}"
                )
            partial = target.with_name(target.name + ".part")
            partial.write_bytes(data)
            partial.replace(target)


# Seconds to wait before each retry of a failed download. The ITU server
# answers 404, 500 and 503 for minutes at a time and then serves the same URL
# again, and CI must not fail on that; the package's pinned sha256 still
# decides whether what arrives is accepted.
RETRY_WAITS = (5, 15, 30, 60, 120)


def download(
    dest,
    url=PACKAGE_URL,
    name=".g729-package.zip.part",
    opener=urllib.request.urlopen,
    sleep=time.sleep,
):
    """Download a package into DEST (never /tmp) and return its path.

    Retries an HTTP error, a connection error or a timeout after each wait in
    RETRY_WAITS, and raises the last error when every attempt failed.
    """
    pathlib.Path(dest).mkdir(parents=True, exist_ok=True)
    target = pathlib.Path(dest) / name
    request = urllib.request.Request(url, headers={"User-Agent": "sipnab-fetch"})
    for attempt, wait in enumerate((*RETRY_WAITS, None)):
        try:
            with opener(request, timeout=120) as response, open(target, "wb") as out:
                while True:
                    block = response.read(1 << 20)
                    if not block:
                        break
                    out.write(block)
            return target
        except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
            if wait is None:
                raise
            print(
                f"fetch-g729-vectors: attempt {attempt + 1} failed ({err}); "
                f"retrying in {wait} s",
                file=sys.stderr,
            )
            sleep(wait)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--zip", type=pathlib.Path, help="use this local copy of the package")
    parser.add_argument(
        "--g7291-zip", type=pathlib.Path, help="use this local copy of the G.729.1 package"
    )
    parser.add_argument(
        "--g7291-only", action="store_true", help="fetch only the G.729.1 package"
    )
    parser.add_argument("dest", nargs="?", type=pathlib.Path)
    args = parser.parse_args(argv)
    dest = args.dest or pathlib.Path(os.environ.get(ENV_VAR) or DEFAULT_DEST)

    packages = [
        (args.g7291_zip, G7291_PACKAGE_URL, G7291_PACKAGE_SIZE, G7291_PACKAGE_SHA256, G7291_PINS)
    ]
    if not args.g7291_only:
        packages.insert(0, (args.zip, PACKAGE_URL, PACKAGE_SIZE, PACKAGE_SHA256, ALL_PINS))
    verified = 0
    for local, url, size, sha256, pins in packages:
        downloaded = None
        try:
            if local is not None:
                package = local
            else:
                downloaded = package = download(dest, url, ".itu-package.zip.part")
            verify_package(package, size, sha256)
            extract(package, dest, pins)
            verified += len(pins)
        except (FetchError, OSError, zipfile.BadZipFile) as err:
            print(f"fetch-g729-vectors: {err}", file=sys.stderr)
            return 1
        finally:
            if downloaded is not None and downloaded.exists():
                downloaded.unlink()
    print(f"fetch-g729-vectors: {verified} files verified in {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
