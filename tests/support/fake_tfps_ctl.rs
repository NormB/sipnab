// SPDX-License-Identifier: MIT OR Apache-2.0

//! A fake `tfps_ctl` for the process-level action tests: answers ban, unban
//! and banned with TFPS's own recorded replies, records every call, and like
//! TFPS remembers what it banned. Shared so the suites cannot drift apart on
//! what TFPS does.

#![allow(dead_code)]

#[path = "executable.rs"]
mod executable;

const BAN: &str = r#"{"ip":"198.51.100.20","action":"ban","applied":true,"refused":null,"expires":null,"source":"operator"}"#;
const UNBAN: &str = r#"{"ip":"198.51.100.20","action":"unban","applied":true,"refused":null,"expires":null,"source":"operator"}"#;
const BANNED: &str = include_str!("../fixtures/tfps-banned-golden.jsonl");

/// A `tfps_ctl` that answers ban, unban and banned, records every call, and
/// fails every ban while a `fail` file sits beside it. Like TFPS, it
/// remembers what it banned and lists it, so a restarted sipnab finds its
/// bans still in force.
pub struct Fake {
    pub dir: tempfile::TempDir,
}

impl Fake {
    pub fn new() -> std::io::Result<Self> {
        let dir = tempfile::tempdir()?;
        let here = dir.path().display();
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$@\" >> \"{here}/argv\"\n\
             case \"$1\" in\n\
             ban) if [ -e \"{here}/fail\" ]; then echo 'tfps: map write failed' >&2; exit 1; fi; \
                  echo \"$3\" >> \"{here}/held\"; echo '{BAN}';;\n\
             unban) : > \"{here}/held.new\"; while read -r ip; do [ \"$ip\" = \"$3\" ] || echo \"$ip\" >> \"{here}/held.new\"; done < \"{here}/held\"; \
                    mv \"{here}/held.new\" \"{here}/held\"; \
                    echo '{UNBAN}';;\n\
             banned) cat <<'SIPNAB_FIXTURE'\n{BANNED}\nSIPNAB_FIXTURE\n\
                     if [ -e \"{here}/held\" ]; then while read -r ip; do \
                     echo \"{{\\\"ip\\\":\\\"$ip\\\",\\\"reason\\\":null,\\\"detail\\\":null,\\\"first_seen\\\":null,\\\"expires\\\":null,\\\"enforced\\\":true}}\"; \
                     done < \"{here}/held\"; fi;;\n\
             *) echo \"unknown subcommand $1\" >&2; exit 2;;\n\
             esac\n"
        );
        let path = dir.path().join("tfps_ctl");
        executable::write_executable(&path, &script)?;
        Ok(Self { dir })
    }

    pub fn path(&self) -> String {
        self.dir.path().join("tfps_ctl").display().to_string()
    }

    pub fn fail_bans(&self) -> std::io::Result<()> {
        std::fs::write(self.dir.path().join("fail"), "")
    }

    pub fn calls(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("argv")).unwrap_or_default()
    }

    /// How many times `tfps_ctl <subcommand>` ran; `banned` is not `ban`.
    pub fn count(&self, subcommand: &str) -> usize {
        self.calls().lines().filter(|l| *l == subcommand).count()
    }
}

// Panicking forms of the functions above, for callers not yet converted to
// return a `Result`. Each is removed when its last caller is converted;
// `unwrap_ratchet_test` counts the `expect` in each.

impl Fake {
    /// [`Fake::new`], panicking on error.
    pub fn new_or_panic() -> Self {
        Self::new().expect("Fake::new")
    }

    /// [`Fake::fail_bans`], panicking on error.
    pub fn fail_bans_or_panic(&self) {
        self.fail_bans().expect("Fake::fail_bans")
    }
}
