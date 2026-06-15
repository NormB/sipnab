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

    // The `audio` feature no longer links libasound into the binary: device
    // output lives in the `sipnab-audio` cdylib plugin, which the binary
    // dlopen's lazily. The binary thus starts fine without libasound — only
    // live playback needs it — so no build-time runtime-dependency warning is
    // required for the `audio` feature anymore.
}

fn git(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}
