// SPDX-License-Identifier: MIT OR Apache-2.0

//! Which TLS libraries is this host running, and could sipnab probe them?
//!
//! The library-level equivalent of `sipnab --uprobe-list`, kept as a worked
//! example because the two facts it prints are the ones that decide whether a
//! uprobe capture will work — and both are easy to get wrong by reasoning
//! instead of measuring.
//!
//! Run it:
//!
//! ```sh
//! cargo run --features native --example uprobe_discover
//! sudo -E cargo run --features native --example uprobe_discover   # sees containers
//! ```
//!
//! Run it twice, once unprivileged. The list gets **shorter**, because
//! `/proc/<pid>/maps` is only readable for processes you own — which is the
//! whole reason a uprobe capture needs root and the reason "found nothing" is
//! an error rather than an empty capture.

#[cfg(all(target_os = "linux", feature = "native"))]
fn main() {
    use sipnab::capture::uprobe::discover;

    let libs = discover::discover();
    if libs.is_empty() {
        eprintln!(
            "Nothing here maps OpenSSL or wolfSSL that this process can see.\n\
             Try again with sudo: /proc/<pid>/maps is readable only for your own\n\
             processes, so an unprivileged run sees a fraction of the host."
        );
        return;
    }

    println!("{} TLS librar(y|ies) in use:\n", libs.len());
    for lib in &libs {
        println!("  {} — {}", lib.flavour.label(), lib.path.display());
        println!(
            "    inode  {} (this, not the path, is its identity)",
            lib.inode
        );
        println!("    pids   {} mapping it", lib.pids.len());
        println!("    symbol {}", lib.flavour.write_symbol());

        // The fact that matters. A path from /proc/<pid>/maps was resolved in
        // the MAPPING process's mount namespace; a uprobe is installed with a
        // path resolved in OURS. For a containerised process those name
        // different files, and probing the bare path attaches to the host's
        // copy while looking entirely successful.
        match lib.probe_path() {
            Some(p) if p == lib.path => {
                println!("    probe  {} (same namespace)", p.display());
            }
            Some(p) => {
                println!("    probe  {}", p.display());
                println!("           ^ reached through /proc/<pid>/root: the process is in a");
                println!("             different mount namespace, so the bare path names a");
                println!("             DIFFERENT file here");
            }
            None => {
                println!("    probe  UNREACHABLE — no path names this inode from here, so");
                println!("           sipnab refuses rather than probing a file that merely");
                println!("           has the right name");
            }
        }
        println!();
    }

    // What a capture would actually attach to, including the refusals.
    match discover::plan_targets(&[], None, &[], libs) {
        Ok(targets) => {
            println!(
                "A capture would install probes on {} target(s):",
                targets.len()
            );
            for t in targets {
                println!("  {}:{}", t.library.display(), t.symbol);
            }
        }
        Err(e) => println!("A capture would REFUSE to start: {e}"),
    }
}

#[cfg(not(all(target_os = "linux", feature = "native")))]
fn main() {
    eprintln!(
        "Uprobe capture is a Linux kernel facility and needs the `native` feature.\n\
         Try: cargo run --features native --example uprobe_discover"
    );
}
