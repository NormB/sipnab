# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: The sipnab contributors

"""Neither the installer nor the download page offers Windows users a path.

Both used to: website/static/install.sh answered a Windows `uname -s` with
"on Windows use WSL or build from source", and the download page's detector
gave a Windows visitor the "Build from source" tab with "run sipnab under
WSL, or build from source". Building sipnab on Windows has never been tried,
so neither suggestion is known to work. The owner's wording replaces both:
sipnab currently focuses on Linux and macOS, Windows is not supported yet,
and pull requests that add Windows support are welcome.

The installer's `detect_os` is driven by sourcing the script with
SIPNAB_INSTALL_TEST=1, as tests/install-sh/run-tests.sh does. The page's
detector is an inline script in website/templates/download.html; it is run
under node by download_detect_harness.js, which reads the script and the
banner's markup out of the template, so these tests hold the code that ships.
"""

import json
import os
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
INSTALL = ROOT / "website" / "static" / "install.sh"
TEMPLATE = ROOT / "website" / "templates" / "download.html"
HARNESS = pathlib.Path(__file__).with_name("download_detect_harness.js")

FOCUS = "sipnab currently focuses on Linux and macOS."
# The owner's example sentence, split at its semicolon: site prose may not
# join sentences with one (site_page_prose_carries_no_semicolons), and the
# installer says the same words as the page.
NOT_YET = "Windows is not supported yet. Pull requests that add Windows support are welcome"
CONTRIBUTING_URL = "https://github.com/NormB/sipnab/blob/main/CONTRIBUTING.md"
OFFERS = re.compile(r"WSL|build from source|build it from source", re.IGNORECASE)

# `uname -s` on Git for Windows (64- and 32-bit), MSYS2, Cygwin, and the value
# some ports of uname print.
WINDOWS_UNAMES = [
    "MINGW64_NT-10.0-19045",
    "MINGW32_NT-10.0-19045",
    "MSYS_NT-10.0-19045",
    "CYGWIN_NT-10.0-19045",
    "Windows_NT",
]
OTHER_UNAMES = ["FreeBSD", "SunOS", "AIX", ""]

MAC = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
UBUNTU = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
FEDORA = "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"
LINUX = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
ANDROID = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Mobile Safari/537.36"
)
IPHONE = (
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
)
SUPPORTED = [
    (MAC, "mac", "macOS"),
    (UBUNTU, "debian", "Debian/Ubuntu"),
    (FEDORA, "debian", "RHEL/Fedora"),
    (LINUX, "linux", "Linux"),
    (ANDROID, "linux", "Linux"),
    (IPHONE, "mac", "iPhone/iPad"),
]
WINDOWS_UAS = [
    # Chrome, Edge and Firefox on Windows 10/11, Internet Explorer 11 on
    # Windows 7, and the Xbox browser.
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Xbox; Xbox One) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/48.0.2564.82 Safari/537.36 Edge/14.14393",
]


def detect_os(uname):
    """Run install.sh's detect_os on one `uname -s` value."""
    return subprocess.run(
        ["sh", "-c", '. "$1" && detect_os "$2"', "sh", str(INSTALL), uname],
        env={**os.environ, "SIPNAB_INSTALL_TEST": "1"},
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def detect_page(ua, arch=None, touch=0):
    """Run the download page's detector for one visitor; return its effects."""
    node = shutil.which("node")
    assert node, "node is required: it runs the download page's detection script"
    config = json.dumps({"ua": ua, "arch": arch, "maxTouchPoints": touch})
    done = subprocess.run(
        [node, str(HARNESS), str(TEMPLATE), config],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert done.returncode == 0, f"the harness failed: {done.stderr}"
    return json.loads(done.stdout)


def banner_markup():
    html = TEMPLATE.read_text(encoding="utf-8")
    start = html.index('<div class="dl-detect" id="dl-detect"')
    return html[start : html.index("{#", start)]


def detection_script():
    html = TEMPLATE.read_text(encoding="utf-8")
    start = html.index("<script>", html.index('id="dl-detect"'))
    return html[start : html.index("</script>", start)]


def element_markup(element_id):
    found = re.search(r'<span id="' + element_id + r'"[^>]*>(.*?)</span>', banner_markup(), re.S)
    assert found, f"#{element_id} is not a <span> in the #dl-detect banner"
    return found


# ── installer: success ─────────────────────────────────────────────────


@pytest.mark.parametrize(("uname", "expected"), [("Linux", "linux"), ("Darwin", "darwin")])
def test_installer_detects_supported_os(uname, expected):
    done = detect_os(uname)
    assert (done.returncode, done.stdout) == (0, expected + "\n"), done.stderr


@pytest.mark.parametrize("uname", ["Linux", "Darwin"])
def test_installer_says_nothing_on_stderr_for_supported_os(uname):
    assert detect_os(uname).stderr == ""


# ── installer: failure ─────────────────────────────────────────────────


@pytest.mark.parametrize("uname", WINDOWS_UNAMES)
def test_installer_rejects_windows(uname):
    done = detect_os(uname)
    assert done.returncode != 0 and done.stdout == "", (done.returncode, done.stdout)


@pytest.mark.parametrize("uname", WINDOWS_UNAMES)
def test_installer_windows_message_states_focus_and_welcomes_pull_requests(uname):
    stderr = detect_os(uname).stderr
    assert FOCUS in stderr and NOT_YET in stderr, stderr


@pytest.mark.parametrize("uname", WINDOWS_UNAMES)
def test_installer_windows_message_links_contributing(uname):
    stderr = detect_os(uname).stderr
    assert CONTRIBUTING_URL in stderr, stderr


@pytest.mark.parametrize("uname", WINDOWS_UNAMES)
def test_installer_windows_message_offers_no_wsl_or_source_build(uname):
    stderr = detect_os(uname).stderr
    assert not OFFERS.search(stderr), stderr


@pytest.mark.parametrize("uname", OTHER_UNAMES)
def test_installer_rejects_other_os_with_focus_line_only(uname):
    done = detect_os(uname)
    assert done.returncode != 0, done.stdout
    assert FOCUS.rstrip(".") in done.stderr, done.stderr
    assert "Windows" not in done.stderr and not OFFERS.search(done.stderr), done.stderr


# ── installer: edge ────────────────────────────────────────────────────


def test_installer_lowercase_mingw_is_not_read_as_windows():
    stderr = detect_os("mingw64_nt-10.0").stderr
    assert "unsupported OS" in stderr and "Windows" not in stderr, stderr


def test_installer_lowercase_linux_stays_rejected():
    assert detect_os("linux").returncode != 0


def test_installer_trailing_space_darwin_stays_rejected():
    assert detect_os("Darwin ").returncode != 0


def test_installer_rejects_shell_text_after_linux():
    done = detect_os("Linux; rm -rf /")
    assert done.returncode != 0 and "Windows" not in done.stderr, done.stderr


def test_installer_prints_format_directives_in_the_name_literally():
    done = detect_os("%s%n")
    assert done.returncode != 0 and 'unsupported OS "%s%n"' in done.stderr, done.stderr


def test_installer_quotes_shell_text_after_a_windows_name():
    done = detect_os("MINGW64_NT-10.0; echo pwned")
    assert done.stdout == "" and 'unsupported OS "MINGW64_NT-10.0; echo pwned"' in done.stderr


def test_installer_windows_message_is_one_line():
    stderr = detect_os("MINGW64_NT-10.0-19045").stderr
    assert stderr.count("\n") == 1 and stderr.endswith("\n"), stderr


def test_installer_source_offers_no_wsl_or_source_build():
    found = OFFERS.findall(INSTALL.read_text(encoding="utf-8"))
    assert not found, f"install.sh still says {found}"


# ── download page: success ────────────────────────────────────────────


@pytest.mark.parametrize(("ua", "os_key", "name"), SUPPORTED)
def test_page_names_a_supported_platform(ua, os_key, name):
    out = detect_page(ua)["elements"]
    banner, plat = out["dl-detect"], out["dl-detect-plat"]
    assert (banner["hidden"], banner["dataOs"], plat["text"]) == (False, os_key, name), out


@pytest.mark.parametrize(("ua", "os_key", "name"), SUPPORTED)
def test_page_keeps_the_windows_line_hidden_for_a_supported_platform(ua, os_key, name):
    out = detect_page(ua)["elements"]
    shown = (out["dl-detect-match"]["hidden"], out["dl-detect-unsupported"]["hidden"])
    assert shown == (False, True), (name, out)


def test_page_marks_the_arm_tile_for_an_arm_mac():
    assert detect_page(MAC, arch="arm")["cpuTiles"] == ["arm"]


def test_page_marks_the_x86_tile_for_an_x86_linux_host():
    assert detect_page(LINUX, arch="x86")["cpuTiles"] == ["x86"]


# ── download page: failure (Windows) ──────────────────────────────────


@pytest.mark.parametrize("ua", WINDOWS_UAS)
def test_page_offers_windows_no_platform(ua):
    banner = detect_page(ua)["elements"]["dl-detect"]
    assert banner["dataOs"] is None, banner


@pytest.mark.parametrize("ua", WINDOWS_UAS)
def test_page_shows_windows_the_focus_line_in_place_of_a_choice(ua):
    out = detect_page(ua)["elements"]
    shown = (out["dl-detect"]["hidden"], out["dl-detect-match"]["hidden"], out["dl-detect-unsupported"]["hidden"])
    assert shown == (False, True, False), out


@pytest.mark.parametrize("ua", WINDOWS_UAS)
def test_page_marks_no_cpu_tile_for_windows(ua):
    assert detect_page(ua, arch="x86")["cpuTiles"] == []


# ── download page: edge ────────────────────────────────────────────────


def test_page_does_not_ask_windows_on_arm_for_its_cpu():
    out = detect_page(WINDOWS_UAS[0], arch="arm")
    assert (out["hintAsked"], out["cpuTiles"]) == (False, []), out


def test_page_leaves_platform_and_note_empty_for_windows():
    out = detect_page(WINDOWS_UAS[0])["elements"]
    assert (out["dl-detect-plat"]["text"], out["dl-detect-note"]["text"]) == ("", ""), out


def test_page_reads_an_empty_user_agent_as_macos():
    out = detect_page("")["elements"]
    assert (out["dl-detect"]["dataOs"], out["dl-detect-unsupported"]["hidden"]) == ("mac", True), out


def test_page_reads_a_desktop_mode_ipad_as_iphone_ipad():
    out = detect_page(MAC, touch=5)["elements"]
    assert (out["dl-detect"]["dataOs"], out["dl-detect-plat"]["text"]) == ("mac", "iPhone/iPad"), out


def test_banner_and_detector_offer_no_wsl_or_source_build():
    # The banner and its script are where a Windows visitor is answered. The
    # page's "Build from source" tab stays: it is for Linux and macOS readers.
    found = OFFERS.findall(banner_markup() + detection_script())
    assert not found, f"the #dl-detect banner or its script still says {found}"


def test_template_mentions_wsl_nowhere():
    found = re.findall(r"WSL", TEMPLATE.read_text(encoding="utf-8"))
    assert not found, f"download.html still mentions WSL {len(found)} time(s)"


def test_detection_script_never_sends_a_visitor_to_the_source_tab():
    assert "'source'" not in detection_script(), "the detector still picks the Source tab"


def test_windows_line_has_the_owner_wording():
    text = re.sub(r"<[^>]+>", "", element_markup("dl-detect-unsupported").group(1))
    assert FOCUS in text and NOT_YET in text, text


def test_windows_line_links_the_contributing_page():
    body = element_markup("dl-detect-unsupported").group(1)
    assert "get_url(path='@/docs/contributing.md')" in body and "CONTRIBUTING.md</a>" in body, body


def test_contributing_page_the_windows_line_links_exists():
    page = ROOT / "website" / "content" / "docs" / "contributing.md"
    assert page.is_file() and 'source = "CONTRIBUTING.md"' in page.read_text(encoding="utf-8")


def test_windows_line_starts_hidden():
    assert re.search(r"\bhidden\b", element_markup("dl-detect-unsupported").group(0).split(">")[0])


def test_match_line_starts_shown():
    opening = element_markup("dl-detect-match").group(0).split(">")[0]
    assert not re.search(r"\bhidden\b", opening), opening
