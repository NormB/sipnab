use std::process::Command;

fn main() {
    // Re-run if git HEAD changes (new commits, checkouts, tags).
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");

    let commit = git(&["rev-parse", "--short=8", "HEAD"]).unwrap_or_default();
    let tag = git(&["describe", "--tags", "--exact-match", "HEAD"]).unwrap_or_default();
    let dirty = git(&["status", "--porcelain"])
        .map(|s| if s.is_empty() { "" } else { "-dirty" })
        .unwrap_or("");

    println!("cargo:rustc-env=SIPNAB_GIT_COMMIT={commit}");
    println!("cargo:rustc-env=SIPNAB_GIT_TAG={tag}");
    println!("cargo:rustc-env=SIPNAB_GIT_DIRTY={dirty}");

    // The `audio` feature is in the default set and dynamically links
    // libasound on Linux: a binary built on a dev box with ALSA present
    // fails at startup on a headless server without it. Warn at build
    // time so the runtime dependency is impossible to miss.
    if std::env::var_os("CARGO_FEATURE_AUDIO").is_some()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
    {
        println!(
            "cargo:warning=sipnab: built with the `audio` feature (in the default set) — \
             the binary needs libasound.so.2 at runtime (Debian/Ubuntu: libasound2, \
             Fedora/RHEL: alsa-lib)"
        );
        println!(
            "cargo:warning=sipnab: for headless hosts, drop it: \
             cargo build --release --no-default-features --features native,tui,tls,hep,api"
        );
    }
}

fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
