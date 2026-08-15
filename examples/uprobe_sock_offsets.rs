// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where does `struct sock` keep its addresses on *this* kernel?
//!
//! The BPF backend has to read a socket's addresses out of kernel memory, and
//! where they sit differs between kernels. Compiling the offsets in would make
//! the program correct on one kernel and **silently wrong** on the next —
//! reading whatever happens to live at that byte and reporting it as an IP
//! address, with no symptom except wrong answers.
//!
//! So sipnab reads them from BTF — the **BPF Type Format**, the kernel's
//! description of its own types — at load time, every time. This example is
//! that lookup on its own, which makes it the quickest way to answer two
//! questions: *can this machine run the BPF backend at all*, and *what did
//! sipnab conclude about its kernel*.
//!
//! Run it:
//!
//! ```sh
//! cargo run --features native --example uprobe_sock_offsets
//! ```
//!
//! It needs no privileges and installs nothing. On a kernel built without
//! `CONFIG_DEBUG_INFO_BTF` it prints the refusal the BPF backend would give
//! you, which is the useful answer rather than a failure.

#[cfg(all(target_os = "linux", feature = "native"))]
fn main() {
    use sipnab::capture::uprobe::btf::{Btf, BtfError, VMLINUX_BTF};

    println!("reading {VMLINUX_BTF}\n");
    let btf = match Btf::from_sys_fs() {
        Ok(btf) => btf,
        Err(BtfError::Absent) => {
            println!(
                "No BTF on this kernel, so the BPF backend cannot run here.\n\
                 That is a property of the kernel build, not a fault: it needs\n\
                 CONFIG_DEBUG_INFO_BTF=y. Use --uprobe-backend tracefs, which\n\
                 needs neither BTF nor a nightly toolchain — it just cannot\n\
                 report the peer."
            );
            return;
        }
        Err(e) => {
            println!("BTF is present but unusable: {e}");
            return;
        }
    };

    match btf.sock_offsets() {
        Ok(off) => {
            println!("struct sock, as this kernel lays it out:\n");
            for (name, at) in [
                ("skc_daddr   (remote IPv4)", off.daddr4),
                ("skc_rcv_saddr (local IPv4)", off.saddr4),
                ("skc_dport   (remote port)", off.dport),
                ("skc_num     (local port)", off.sport),
                ("skc_family", off.family),
                ("skc_v6_daddr", off.daddr6),
                ("skc_v6_rcv_saddr", off.saddr6),
            ] {
                println!("  {name:<28} +{at}");
            }
            println!(
                "\nsipnab writes these into a map before either program attaches.\n\
                 Until it does, `valid` is 0 and the program refuses to read a\n\
                 socket at all — because 0 is itself a legal offset, and a\n\
                 program reading there would report the start of the struct as\n\
                 an address."
            );

            // The ports are the interesting ones: on a real kernel they live
            // inside an anonymous union, so finding them at all proves the
            // walk descends into unnamed members rather than only scanning the
            // top level.
            assert!(
                off.dport > 0 && off.sport > off.dport,
                "skc_dport and skc_num sit adjacent inside an anonymous union"
            );
            println!(
                "\nBoth ports resolved, which means the walk descended into the\n\
                 anonymous union they live in rather than only reading named\n\
                 top-level members."
            );
        }
        Err(e) => println!(
            "This kernel publishes BTF but not the members sipnab needs: {e}\n\
             The BPF backend refuses rather than reading a guessed offset."
        ),
    }
}

#[cfg(not(all(target_os = "linux", feature = "native")))]
fn main() {
    eprintln!(
        "BTF is a Linux kernel facility and this example needs the `native` \
         feature.\nTry: cargo run --features native --example uprobe_sock_offsets"
    );
}
