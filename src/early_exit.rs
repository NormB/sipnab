// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: The sipnab contributors

//! Every way a run ends before `bootstrap::launch`, and what it does with
//! root.
//!
//! `bootstrap::launch` is where a capture run drops privileges. A command
//! that ends before it never reached that drop: started as root, it stayed
//! root (COMMANDS-KEEP-ROOT). [`EARLY_EXITS`] is the one list of those
//! commands. Each row names a [`Plan`], [`action`] decides from the row and
//! the command line what a run does, and [`confine`] carries it out.
//! `tests/threads_at_privilege_drop_test.rs` fails when `src/main.rs` gains
//! an exit this table does not hold.
//!
//! Seven rows carry [`Plan::ParsesNamedFile`]: commands that parse a file
//! the caller named. As root they only name, open and read: the inputs by
//! handle or whole, the key files, the directory listings. They drop in
//! [`confine`] and judge, unwrap and parse from those handles as the user
//! they dropped to, so a capture only root can read is still read.

use crate::privilege::{self, DropSkip, DropTarget};
use std::path::{Path, PathBuf};

/// What a command that ends before `bootstrap::launch` does when it was
/// started as root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Plan {
    /// Binds its listener and reads its key files as root, then drops before
    /// it accepts a connection.
    Listener,
    /// Reads its secrets as root, then drops before its first connection.
    NetworkClient,
    /// Reads its key files as root, then drops before it opens a file it
    /// reports on.
    Reader,
    /// Keeps the caller's privileges; the row's reason says why.
    Keeps,
    /// Parses a file the caller named: names, opens and reads its inputs
    /// and its key files as root, then drops before it judges or parses a
    /// byte of them.
    ParsesNamedFile,
    /// Drops on a path of its own, which the row's reason names.
    OwnDrop,
}

impl Plan {
    /// Whether a run under this plan drops in [`confine`].
    #[must_use]
    pub fn drops_here(self) -> bool {
        matches!(
            self,
            Plan::Listener | Plan::NetworkClient | Plan::Reader | Plan::ParsesNamedFile
        )
    }
}

/// One way a run ends before `bootstrap::launch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EarlyExit {
    /// The command or flag, as an operator types it, or the kind of error.
    pub name: &'static str,
    /// The step of `main` that ends the run.
    pub step: &'static str,
    /// What the run does with root.
    pub plan: Plan,
    /// Why, in one sentence.
    pub reason: &'static str,
}

/// The reason every [`Plan::ParsesNamedFile`] row carries.
const PARSES: &str = "parses a file the caller named; opens and reads its inputs and key files \
                      as root, then drops before it judges, unwraps or parses them";

/// The reason of an exit that reports an error and reads nothing more.
const ERROR_EXIT: &str = "reports an error and ends; reads no input from outside";

/// Build one row.
const fn row(
    name: &'static str,
    step: &'static str,
    plan: Plan,
    reason: &'static str,
) -> EarlyExit {
    EarlyExit {
        name,
        step,
        plan,
        reason,
    }
}

/// Every way a run ends before `bootstrap::launch`, in the order of `main`'s
/// steps.
pub const EARLY_EXITS: [EarlyExit; 37] = [
    row(
        "--internal-kill-worker",
        "0",
        Plan::OwnDrop,
        "the kill worker drops in `worker_process::harden` before it starts its pumps",
    ),
    row(
        "g729 install",
        "0b",
        Plan::OwnDrop,
        "downloads, checks and unpacks the package in a child started as --user, the config \
         user or nobody (`app::g729_install::download_table`); root only checks the table file \
         the child sends and installs it by rename into a directory root may own; `--from` uses \
         no network, and it and --no-priv-drop keep the caller's privileges",
    ),
    row(
        "g729 internal-fetch",
        "0b",
        Plan::Keeps,
        "refuses to start as root; `sipnab g729 install` starts it as the user it drops to, and \
         it writes the table file to its standard output",
    ),
    row(
        "g729 status",
        "0b",
        Plan::Keeps,
        "reads the installed table file and prints its state",
    ),
    row(
        "fleet inventory",
        "0c",
        Plan::NetworkClient,
        "reads the hosts file and every token file as root, then drops before it asks a host",
    ),
    row(
        "fleet keygen",
        "0c",
        Plan::Keeps,
        "writes one key file for the caller; reads no input from outside",
    ),
    row(
        "fleet serve",
        "0c",
        Plan::Listener,
        "reads its keys and binds as root, then drops before it opens the store or accepts",
    ),
    row(
        "fleet verify",
        "0c",
        Plan::Reader,
        "reads its key files as root, then drops before it lists the history directory or \
         opens a history file",
    ),
    row(
        "--help",
        "1",
        Plan::Keeps,
        "prints text built into the binary",
    ),
    row(
        "--version",
        "1",
        Plan::Keeps,
        "prints text built into the binary",
    ),
    row("argument error", "1", Plan::Keeps, ERROR_EXIT),
    row("archive password error", "1b", Plan::Keeps, ERROR_EXIT),
    row(
        "--completions",
        "2",
        Plan::Keeps,
        "prints a script built from the command line's definition",
    ),
    row(
        "--print-yang-module",
        "2",
        Plan::Keeps,
        "prints text built into the binary",
    ),
    row(
        "--setup-caps",
        "2",
        Plan::Keeps,
        "grants the binary its capture capabilities, which needs root",
    ),
    row("--show-frame", "2", Plan::ParsesNamedFile, PARSES),
    row("--write-annotated", "2", Plan::ParsesNamedFile, PARSES),
    row("--notes refusal", "2", Plan::Keeps, ERROR_EXIT),
    row("--strip-secrets", "2", Plan::ParsesNamedFile, PARSES),
    row("--find-in-files", "2", Plan::ParsesNamedFile, PARSES),
    row("--compare-captures", "2", Plan::ParsesNamedFile, PARSES),
    row("--vcon-validate", "2", Plan::ParsesNamedFile, PARSES),
    row("validation error", "3", Plan::Keeps, ERROR_EXIT),
    row("provenance error", "3b", Plan::Keeps, ERROR_EXIT),
    row(
        "--mint-token",
        "4",
        Plan::Keeps,
        "reads the caller's signing key and prints a token; reads no input from outside",
    ),
    row(
        "--vcon-forward",
        "4b",
        Plan::NetworkClient,
        "reads its credentials as root, then drops before it connects to the store",
    ),
    row(
        "--vcon-fetch",
        "4c",
        Plan::NetworkClient,
        "reads its credentials and trust files as root, then drops before it connects",
    ),
    row(
        "--vcon-spool-status",
        "4d",
        Plan::Keeps,
        "lists the spool's directories and failure records, which sipnab wrote; a spool private \
         to root stays readable",
    ),
    row("--vcon-resign", "4e", Plan::ParsesNamedFile, PARSES),
    row(
        "--vcon-audio-fetch",
        "4f",
        Plan::NetworkClient,
        "reads the vCon and its keys as root, then drops before it connects; with \
         `--vcon-audio-fetch-local` it makes no connection and keeps the caller's privileges",
    ),
    row("config error", "5", Plan::Keeps, ERROR_EXIT),
    row(
        "--panic-selftest",
        "5b",
        Plan::Keeps,
        "panics on purpose to exercise the crash report; reads no input from outside",
    ),
    row(
        "--dump-config",
        "6",
        Plan::Keeps,
        "prints the configuration the caller's own files gave",
    ),
    row(
        "--journal-show",
        "6a",
        Plan::Keeps,
        "reads the action journal sipnab wrote, which may be private to root",
    ),
    row(
        "--revert-actions",
        "6a",
        Plan::Keeps,
        "backs out what a run did to other systems with the privileges that run had",
    ),
    row(
        "--uprobe-list",
        "6b",
        Plan::Keeps,
        "reads other processes' memory maps, which needs root",
    ),
    row("plan error", "7", Plan::Keeps, ERROR_EXIT),
];

/// The exits after the plan is made, kept apart so [`EARLY_EXITS`] stays in
/// step order and its length is checked by the compiler.
pub const LATE_EXITS: [EarlyExit; 3] = [
    row(
        "--relay-holdings",
        "7b",
        Plan::NetworkClient,
        "drops before it asks the relay",
    ),
    row(
        "--relay-sessions",
        "7c",
        Plan::NetworkClient,
        "drops before it asks the relay",
    ),
    row(
        "--cores",
        "8",
        Plan::OwnDrop,
        "`prepare_cores_inputs` drops, then judges the set `plan` opened as root, before a reader starts",
    ),
];

/// Every row of both tables, in step order.
pub fn rows() -> impl Iterator<Item = &'static EarlyExit> {
    EARLY_EXITS.iter().chain(LATE_EXITS.iter())
}

/// The row named `name`, or `None` when the table holds no such exit.
#[must_use]
pub fn early_exit(name: &str) -> Option<&'static EarlyExit> {
    rows().find(|row| row.name == name)
}

/// What the command line and the process say about a drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Asked<'a> {
    /// Whether the process is root.
    pub root: bool,
    /// `--no-priv-drop`, or `[privilege] no_priv_drop`.
    pub no_priv_drop: bool,
    /// `--user`.
    pub flag_user: Option<&'a str>,
    /// `[privilege] user`, for a command that reads the config file.
    pub config_user: Option<&'a str>,
}

/// What a run does with its privileges before it does its work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<'a> {
    /// The process is not root: nothing changes.
    Unchanged,
    /// The row keeps the caller's privileges, for the reason it gives.
    Keep(&'static str),
    /// `--no-priv-drop`: root is kept and one warning line says so.
    KeepWarned,
    /// Root on macOS with no user named: root is kept, as a capture run
    /// keeps it there, and one warning line says so.
    KeepOnMacos,
    /// Drop to this user.
    DropTo(&'a str),
}

/// What a run of `exit` does with its privileges, decided from `asked`.
///
/// The target is the one a capture run uses: `--user`, else the config
/// user, else `nobody`. A process that is not root changes in nothing.
#[must_use]
pub fn action<'a>(exit: &EarlyExit, asked: Asked<'a>) -> Action<'a> {
    if !asked.root {
        return Action::Unchanged;
    }
    if !exit.plan.drops_here() {
        return Action::Keep(exit.reason);
    }
    let user = asked.flag_user.or(asked.config_user);
    match skip(asked, user) {
        Some(DropSkip::NotRoot) => Action::Unchanged,
        Some(DropSkip::Disabled) => Action::KeepWarned,
        Some(DropSkip::MacosWithoutUser) => Action::KeepOnMacos,
        None => Action::DropTo(user.unwrap_or(privilege::DEFAULT_DROP_USER)),
    }
}

/// What a run must be able to do with a path after the drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Read a file.
    Read,
    /// Read and rewrite a file.
    ReadWrite,
    /// Create, rename and remove entries in a directory.
    WriteDir,
    /// List a directory and open the entries in it.
    ReadDir,
}

impl Access {
    /// The permission bits this access needs on the path itself.
    #[must_use]
    pub fn bits(self) -> u32 {
        match self {
            Access::Read => 0o4,
            Access::ReadWrite => 0o6,
            Access::WriteDir => 0o3,
            Access::ReadDir => 0o5,
        }
    }

    /// The access as the refusal words it.
    #[must_use]
    pub fn words(self) -> &'static str {
        match self {
            Access::Read | Access::ReadDir => "read",
            Access::ReadWrite => "read and write",
            Access::WriteDir => "write in",
        }
    }
}

/// A path a command needs after the drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Need {
    /// The path.
    pub path: PathBuf,
    /// The flag or setting that named it, for the refusal.
    pub what: &'static str,
    /// What the run does with it.
    pub access: Access,
}

/// The needs of a directory tree a run keeps files in: every directory
/// under `root`, `root` included, to write in, and every file to read. A
/// tree that does not exist yet has none: the run creates it. Symbolic links
/// are not followed.
#[must_use]
pub fn tree_needs(root: &Path, what: &'static str) -> Vec<Need> {
    tree_needs_with(root, what, Access::WriteDir)
}

/// The needs of a directory tree a run only reads: every directory under
/// `root`, `root` included, to list, and every file to read. A tree that
/// does not exist has none. Symbolic links are not followed.
#[must_use]
pub fn read_tree_needs(root: &Path, what: &'static str) -> Vec<Need> {
    tree_needs_with(root, what, Access::ReadDir)
}

/// The needs of the tree under `root`: `dir_access` on every directory,
/// `root` included, and a read of every file.
fn tree_needs_with(root: &Path, what: &'static str, dir_access: Access) -> Vec<Need> {
    let mut needs = Vec::new();
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        needs.push(Need {
            path: dir,
            what,
            access: dir_access,
        });
        for entry in entries.flatten() {
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => dirs.push(entry.path()),
                Ok(kind) if kind.is_file() => needs.push(Need {
                    path: entry.path(),
                    what,
                    access: Access::Read,
                }),
                _ => {}
            }
        }
    }
    needs
}

/// The need of a directory a run creates when it is absent: to write in
/// `dir`, or, while `dir` does not exist, in the nearest directory above it
/// that does.
#[must_use]
pub fn creatable_dir(dir: &Path, what: &'static str) -> Need {
    let nearest = dir
        .ancestors()
        .find(|path| !path.as_os_str().is_empty() && path.exists())
        .unwrap_or(Path::new("."));
    Need {
        path: nearest.to_path_buf(),
        what,
        access: Access::WriteDir,
    }
}

/// The owner, group and mode of one path, as `stat` gives them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The owner's uid.
    pub uid: u32,
    /// The group's gid.
    pub gid: u32,
    /// The mode bits.
    pub mode: u32,
}

/// Whether a process with `uid` and the one group `gid` is granted `bits`
/// (read 4, write 2, search 1) on `entry` by its mode. A run that dropped
/// holds no supplementary group, so one gid is the whole answer. Access
/// lists are not read.
#[must_use]
pub fn permits(entry: Entry, uid: u32, gid: u32, bits: u32) -> bool {
    // The kernel reads one class only: the owner's when the uid matches, else
    // the group's when the gid matches, else the others'.
    let shift = if entry.uid == uid {
        6
    } else if entry.gid == gid {
        3
    } else {
        0
    };
    (entry.mode >> shift) & bits & 0o7 == bits & 0o7
}

/// Whether `uid`/`gid` can search every one of `ancestors` and is granted
/// `access` on `leaf`.
#[must_use]
pub fn reaches(ancestors: &[Entry], leaf: Entry, uid: u32, gid: u32, access: Access) -> bool {
    ancestors.iter().all(|dir| permits(*dir, uid, gid, 0o1))
        && permits(leaf, uid, gid, access.bits())
}

/// The user `sudo` was called by, when the refusal can offer it: the name
/// is set, is not root, is not the target the run already dropped to, holds
/// only characters a shell passes through unquoted, and `can` says that user
/// has the access the target lacks.
#[must_use]
pub fn sudo_user_offer<'a>(
    sudo_user: Option<&'a str>,
    target: &str,
    can: impl Fn(&str) -> bool,
) -> Option<&'a str> {
    let user = sudo_user?;
    let plain = user
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    let offered =
        !user.is_empty() && plain && !user.starts_with('-') && user != "root" && user != target;
    (offered && can(user)).then_some(user)
}

/// The refusal of a start: `command`, started as root, runs as `target`,
/// which lacks `need`. Names the three ways out: change the owner, name
/// another user (the one `offer` holds, when there is one), or keep root.
#[must_use]
pub fn refusal(command: &str, need: &Need, target: &str, offer: Option<&str>) -> String {
    let path = need.path.display();
    let user_way = match offer {
        Some(user) => format!("run it with --user {user}, who can"),
        None => "run it with --user USER, naming a user who can".to_string(),
    };
    let access = need.access.words();
    let what = need.what;
    format!(
        "{command}: started as root, this command runs as user '{target}', and '{target}' \
         cannot {access} '{path}' ({what}). Nothing was created. Choose one: chown {target} \
         '{path}'; {user_way}; or pass --no-priv-drop to keep root"
    )
}

/// Print what [`confine`] refused, on stderr, for a command that has no
/// line of its own to put it in.
///
/// # Side effects
///
/// Writes one line to standard error.
pub fn report(refusal: &str) {
    stderr_line!("{refusal}");
}

/// The line a run logs when `--no-priv-drop` keeps root for `command`.
#[must_use]
pub fn kept_root_warning(command: &str) -> String {
    let nobody = privilege::DEFAULT_DROP_USER;
    format!(
        "{command}: running as root because --no-priv-drop was given; without it this command \
         runs as --user, or as '{nobody}'"
    )
}

/// The owner, group and mode of `path`.
fn entry_of(path: &Path) -> Option<Entry> {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata(path).ok()?;
    Some(Entry {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode(),
    })
}

/// Whether the user named `user` is granted `need` by the modes of the path
/// and of every directory above it. A user that does not exist, or a path
/// that does not, is granted nothing.
#[must_use]
pub fn user_can(user: &str, need: &Need) -> bool {
    let Ok((uid, gid)) = privilege::resolve_user(user) else {
        return false;
    };
    let Ok(path) = std::fs::canonicalize(&need.path) else {
        return false;
    };
    let Some(leaf) = entry_of(&path) else {
        return false;
    };
    let ancestors: Option<Vec<Entry>> = path.ancestors().skip(1).map(entry_of).collect();
    ancestors.is_some_and(|dirs| reaches(&dirs, leaf, uid, gid, need.access))
}

/// Whether this process, as it now is, has `need`. The kernel answers, so
/// access lists and mount options count. A file that does not exist yet is
/// not a lack: the run creates it, and its directory is a need of its own.
///
/// The question is the one a capture run asks about its outputs after its
/// drop ([`crate::capture::writer::effective_access`]).
fn holds(need: &Need) -> bool {
    use crate::capture::writer::{AccessWanted, effective_access};
    let wanted = match need.access {
        Access::Read => AccessWanted::Read,
        Access::ReadWrite => AccessWanted::ReadAndWrite,
        Access::WriteDir => AccessWanted::WriteAndSearch,
        Access::ReadDir => AccessWanted::ReadAndSearch,
    };
    match effective_access(&need.path, wanted) {
        Ok(()) => true,
        Err(e) => need.access != Access::WriteDir && e.kind() == std::io::ErrorKind::NotFound,
    }
}

/// Carry out the plan of the exit named `name` before the command does its
/// work: drop to the target [`action`] names and check that the target holds
/// every one of `needs`.
///
/// Call it after the command read its secrets and bound its listener, and
/// before it creates a file, opens a store or makes a connection.
///
/// # Returns
///
/// The account the process dropped to, or `None` when nothing changed.
///
/// # Errors
///
/// The table holds no row `name`; the target user does not exist; the drop
/// failed; or the target lacks one of `needs` ([`refusal`]). The caller
/// reports the text and ends the run: nothing was created.
///
/// # Side effects
///
/// Changes the process's uid, gid and groups, and logs one line.
pub fn confine(name: &str, asked: Asked<'_>, needs: &[Need]) -> Result<Option<DropTarget>, String> {
    let exit = early_exit(name).ok_or_else(|| format!("{name}: no early-exit row"))?;
    let user = match action(exit, asked) {
        Action::Unchanged | Action::Keep(_) => return Ok(None),
        Action::KeepWarned => {
            tracing::warn!("{}", kept_root_warning(name));
            return Ok(None);
        }
        Action::KeepOnMacos => {
            // The capture run's own rule and warning line.
            let _ = privilege::drop_is_skipped(None, false, true);
            return Ok(None);
        }
        Action::DropTo(user) => user,
    };
    let target = privilege::resolve_drop_target(Some(user), false)
        .map_err(|e| format!("{name}: failed to drop privileges: {e}"))?
        .ok_or_else(|| format!("{name}: failed to drop privileges: no target for '{user}'"))?;
    privilege::drop_to(&target).map_err(|e| format!("{name}: failed to drop privileges: {e}"))?;
    if let Some(need) = needs.iter().find(|need| !holds(need)) {
        let sudo_user = std::env::var("SUDO_USER").ok();
        let offer = sudo_user_offer(sudo_user.as_deref(), target.user(), |user| {
            user_can(user, need)
        });
        return Err(refusal(name, need, target.user(), offer));
    }
    Ok(Some(target))
}

/// Proof that a command that parses a named file carried out its plan:
/// that [`confine_file_command`] ran and did not refuse. The step of such a
/// command that parses its input takes one, so the parse cannot be written
/// before the drop. Only [`confine_file_command`] makes one.
#[derive(Debug)]
pub struct Confined(());

impl Confined {
    /// A proof for a test that parses without a process to confine. Its
    /// one caller, `app::vcon_resign::run`, exists with the `vcon` feature.
    #[cfg(all(test, feature = "vcon"))]
    pub(crate) fn in_a_test() -> Self {
        Self(())
    }
}

/// [`confine`] for a command that parses a file the caller named
/// ([`Plan::ParsesNamedFile`]). Call it after the command opened and read
/// its inputs and before it judges or parses a byte of them.
///
/// # Errors
///
/// `name` is not such a command, or what [`confine`] refuses.
///
/// # Side effects
///
/// As [`confine`].
pub fn confine_file_command(
    name: &str,
    asked: Asked<'_>,
    needs: &[Need],
) -> Result<Confined, String> {
    let exit = early_exit(name)
        .filter(|exit| exit.plan == Plan::ParsesNamedFile)
        .ok_or_else(|| format!("{name}: not a command that parses a named file"))?;
    if action(exit, asked) == Action::KeepWarned {
        // Printed, not logged: a run that reads `-I` without `--no-tui` logs
        // errors only, and the line that says root was kept must reach the
        // operator whatever the log shows.
        report(&kept_root_warning(name));
    } else {
        confine(name, asked, needs)?;
    }
    Ok(Confined(()))
}

/// [`Asked`] for this process: whether it is root, and the three settings.
#[must_use]
pub fn asked<'a>(
    flag_user: Option<&'a str>,
    config_user: Option<&'a str>,
    no_priv_drop: bool,
) -> Asked<'a> {
    Asked {
        root: privilege::is_root(),
        no_priv_drop,
        flag_user,
        config_user,
    }
}

/// The skip rule of a capture run, for [`action`].
fn skip(asked: Asked<'_>, user: Option<&str>) -> Option<DropSkip> {
    privilege::drop_skip(user, asked.no_priv_drop, asked.root)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROOT: Asked<'static> = Asked {
        root: true,
        no_priv_drop: false,
        flag_user: None,
        config_user: None,
    };

    fn exit(name: &str) -> &'static EarlyExit {
        let found = early_exit(name);
        assert!(found.is_some(), "the table has no row {name}");
        found.unwrap_or(&EARLY_EXITS[0])
    }

    fn need(path: &str, access: Access) -> Need {
        Need {
            path: PathBuf::from(path),
            what: "--store",
            access,
        }
    }

    const OWNER_ONLY: Entry = Entry {
        uid: 0,
        gid: 0,
        mode: 0o700,
    };

    // ---- success: a root run of a dropping row drops to the right user ----

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_root_listener_with_no_user_drops_to_nobody() {
        assert_eq!(
            action(exit("fleet serve"), ROOT),
            Action::DropTo("nobody"),
            "the default target is the capture run's"
        );
    }

    #[test]
    fn a_root_listener_drops_to_the_flag_user() {
        let asked = Asked {
            flag_user: Some("sipnab"),
            ..ROOT
        };
        assert_eq!(
            action(exit("fleet serve"), asked),
            Action::DropTo("sipnab"),
            "--user names the target"
        );
    }

    #[test]
    fn a_root_client_drops_to_the_config_user() {
        let asked = Asked {
            config_user: Some("voip"),
            ..ROOT
        };
        assert_eq!(
            action(exit("--vcon-forward"), asked),
            Action::DropTo("voip"),
            "[privilege] user names the target when --user is absent"
        );
    }

    #[test]
    fn the_flag_user_wins_over_the_config_user() {
        let asked = Asked {
            flag_user: Some("a"),
            config_user: Some("b"),
            ..ROOT
        };
        assert_eq!(
            action(exit("--vcon-fetch"), asked),
            Action::DropTo("a"),
            "--user is read before the config file's user"
        );
    }

    #[test]
    fn every_network_client_row_drops_when_a_user_is_named() {
        let asked = Asked {
            flag_user: Some("u"),
            ..ROOT
        };
        for name in [
            "fleet inventory",
            "--vcon-forward",
            "--vcon-fetch",
            "--vcon-audio-fetch",
            "--relay-holdings",
            "--relay-sessions",
        ] {
            assert_eq!(action(exit(name), asked), Action::DropTo("u"), "{name}");
        }
    }

    #[test]
    fn a_run_that_is_not_root_changes_in_nothing() {
        for row in rows() {
            let asked = Asked {
                root: false,
                flag_user: Some("u"),
                ..ROOT
            };
            assert_eq!(action(row, asked), Action::Unchanged, "{}", row.name);
        }
    }

    #[test]
    fn a_keeper_row_keeps_root_and_gives_its_reason() {
        let row = exit("--setup-caps");
        assert_eq!(
            action(row, ROOT),
            Action::Keep(row.reason),
            "a keeper names its reason"
        );
    }

    #[test]
    fn a_mode_only_grant_to_the_owner_is_read() {
        assert!(
            permits(OWNER_ONLY, 0, 5, 0o7),
            "the owner holds the owner bits"
        );
    }

    #[test]
    fn a_group_grant_is_read_for_the_group() {
        let dir = Entry {
            uid: 0,
            gid: 7,
            mode: 0o770,
        };
        assert!(permits(dir, 9, 7, 0o3), "the group holds the group bits");
    }

    #[test]
    fn an_other_grant_is_read_for_everyone_else() {
        let dir = Entry {
            uid: 0,
            gid: 0,
            mode: 0o755,
        };
        assert!(permits(dir, 9, 9, 0o5), "others hold the other bits");
    }

    #[test]
    fn a_path_is_reached_through_searchable_ancestors() {
        let open = Entry {
            uid: 0,
            gid: 0,
            mode: 0o755,
        };
        let mine = Entry {
            uid: 9,
            gid: 9,
            mode: 0o700,
        };
        assert!(
            reaches(&[open, open], mine, 9, 9, Access::WriteDir),
            "searchable ancestors and an owned directory"
        );
    }

    #[test]
    fn the_sudo_user_is_offered_when_it_can() {
        assert_eq!(
            sudo_user_offer(Some("alice"), "nobody", |_| true),
            Some("alice"),
            "a caller who has the access is offered"
        );
    }

    #[test]
    fn the_refusal_names_the_three_ways_out() {
        let text = refusal(
            "fleet serve",
            &need("/var/lib/sipnab/center.store", Access::ReadWrite),
            "nobody",
            None,
        );
        for part in [
            "fleet serve",
            "/var/lib/sipnab/center.store",
            "--store",
            "'nobody'",
            "chown nobody",
            "--user",
            "--no-priv-drop",
        ] {
            assert!(text.contains(part), "missing {part:?} in: {text}");
        }
    }

    #[test]
    fn the_refusal_shows_the_offered_command() {
        let text = refusal(
            "--vcon-fetch",
            &need("/home/alice/out", Access::WriteDir),
            "nobody",
            Some("alice"),
        );
        assert!(
            text.contains("--user alice"),
            "the exact flag for the caller: {text}"
        );
    }

    // ---- failure: a run keeps root, or an offer or a grant is withheld ----

    #[test]
    fn no_priv_drop_keeps_root_with_a_warning() {
        let asked = Asked {
            no_priv_drop: true,
            flag_user: Some("u"),
            ..ROOT
        };
        assert_eq!(
            action(exit("fleet serve"), asked),
            Action::KeepWarned,
            "--no-priv-drop wins over --user"
        );
    }

    #[test]
    fn no_priv_drop_on_a_keeper_is_not_warned_about() {
        let asked = Asked {
            no_priv_drop: true,
            ..ROOT
        };
        let row = exit("--dump-config");
        assert_eq!(
            action(row, asked),
            Action::Keep(row.reason),
            "a keeper never dropped, so the flag changes nothing"
        );
    }

    // ---- the commands that parse a named file (COMMANDS-PARSE-AS-ROOT) ----

    /// The seven, in the order of `main`'s steps.
    const FILE_COMMANDS: [&str; 7] = [
        "--show-frame",
        "--write-annotated",
        "--strip-secrets",
        "--find-in-files",
        "--compare-captures",
        "--vcon-validate",
        "--vcon-resign",
    ];

    #[test]
    fn confining_a_file_command_that_is_not_root_gives_the_proof() {
        let asked = Asked {
            root: false,
            ..ROOT
        };
        for name in FILE_COMMANDS {
            assert!(
                confine_file_command(name, asked, &[]).is_ok(),
                "{name}: an ordinary user's run is confined as it stands"
            );
        }
    }

    #[test]
    fn a_row_of_another_plan_gets_no_file_command_proof() {
        let asked = Asked {
            root: false,
            ..ROOT
        };
        for name in ["fleet serve", "--vcon-fetch", "--cores", "--dump-config"] {
            let refused = confine_file_command(name, asked, &[]);
            assert!(
                refused.is_err_and(|e| e.contains("not a command that parses a named file")),
                "{name} is not a file command"
            );
        }
    }

    #[test]
    fn a_name_with_no_row_gets_no_file_command_proof() {
        let refused = confine_file_command("--no-such-flag", ROOT, &[]);
        assert!(
            refused.is_err_and(|e| e.starts_with("--no-such-flag:")),
            "a name the table does not hold is refused before anything is dropped"
        );
    }

    #[test]
    fn the_seven_file_commands_carry_the_parse_plan() {
        for name in FILE_COMMANDS {
            assert_eq!(exit(name).plan, Plan::ParsesNamedFile, "{name}");
        }
    }

    #[test]
    fn the_parse_plan_rows_are_the_seven_in_step_order() {
        let names: Vec<&str> = rows()
            .filter(|row| row.plan == Plan::ParsesNamedFile)
            .map(|row| row.name)
            .collect();
        assert_eq!(names, FILE_COMMANDS, "the rows that parse a named file");
    }

    #[test]
    fn the_parse_plan_drops_here() {
        assert!(
            Plan::ParsesNamedFile.drops_here(),
            "a command that parses a named file drops in confine"
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_root_file_command_with_no_user_drops_to_nobody() {
        for name in FILE_COMMANDS {
            assert_eq!(action(exit(name), ROOT), Action::DropTo("nobody"), "{name}");
        }
    }

    #[test]
    fn a_root_file_command_drops_to_the_flag_user() {
        let asked = Asked {
            flag_user: Some("u"),
            ..ROOT
        };
        for name in FILE_COMMANDS {
            assert_eq!(action(exit(name), asked), Action::DropTo("u"), "{name}");
        }
    }

    #[test]
    fn a_root_file_command_drops_to_the_config_user() {
        let asked = Asked {
            config_user: Some("c"),
            ..ROOT
        };
        for name in FILE_COMMANDS {
            assert_eq!(action(exit(name), asked), Action::DropTo("c"), "{name}");
        }
    }

    #[test]
    fn the_flag_user_outranks_the_config_user_for_a_file_command() {
        let asked = Asked {
            flag_user: Some("u"),
            config_user: Some("c"),
            ..ROOT
        };
        for name in FILE_COMMANDS {
            assert_eq!(action(exit(name), asked), Action::DropTo("u"), "{name}");
        }
    }

    #[test]
    fn a_file_command_never_keeps_root_for_a_reason_of_its_row() {
        let asked = Asked {
            flag_user: Some("u"),
            ..ROOT
        };
        for name in FILE_COMMANDS {
            assert!(
                !matches!(action(exit(name), asked), Action::Keep(_)),
                "{name} keeps root"
            );
        }
    }

    #[test]
    fn no_row_waits_for_a_later_change() {
        for row in rows() {
            assert!(
                !row.reason.contains("for now") && !row.reason.contains("COMMANDS-PARSE-AS-ROOT"),
                "{} still keeps root for now: {}",
                row.name,
                row.reason
            );
        }
    }

    #[test]
    fn a_file_command_that_is_not_root_changes_in_nothing() {
        let asked = Asked {
            root: false,
            flag_user: Some("u"),
            ..ROOT
        };
        for name in FILE_COMMANDS {
            assert_eq!(action(exit(name), asked), Action::Unchanged, "{name}");
        }
    }

    #[test]
    fn a_file_command_with_no_priv_drop_keeps_root_with_the_warning() {
        let asked = Asked {
            no_priv_drop: true,
            ..ROOT
        };
        for name in FILE_COMMANDS {
            assert_eq!(action(exit(name), asked), Action::KeepWarned, "{name}");
        }
    }

    #[test]
    fn no_priv_drop_outranks_a_named_user_for_a_file_command() {
        let asked = Asked {
            no_priv_drop: true,
            flag_user: Some("u"),
            config_user: Some("c"),
            ..ROOT
        };
        for name in FILE_COMMANDS {
            assert_eq!(action(exit(name), asked), Action::KeepWarned, "{name}");
        }
    }

    #[test]
    fn a_file_command_row_says_what_runs_as_root() {
        for name in FILE_COMMANDS {
            let reason = exit(name).reason;
            assert!(
                reason.contains("as root") && reason.contains("drops"),
                "{name}: the reason does not say what runs as root and that it drops: {reason}"
            );
        }
    }

    #[test]
    fn the_file_commands_of_step_2_and_step_4e_keep_their_steps() {
        for name in FILE_COMMANDS {
            let want = if name == "--vcon-resign" { "4e" } else { "2" };
            assert_eq!(exit(name).step, want, "{name}");
        }
    }

    #[test]
    fn an_own_drop_row_is_not_dropped_here() {
        let row = exit("--cores");
        assert_eq!(
            action(row, ROOT),
            Action::Keep(row.reason),
            "its own path drops"
        );
    }

    #[test]
    fn an_unknown_name_has_no_row() {
        assert_eq!(early_exit("--no-such-flag"), None, "no row is invented");
    }

    #[test]
    fn confine_refuses_a_name_the_table_lacks() {
        let err = confine("--no-such-flag", ROOT, &[]).err();
        assert_eq!(
            err.as_deref(),
            Some("--no-such-flag: no early-exit row"),
            "a command cannot drop under a row that does not exist"
        );
    }

    #[test]
    fn a_stranger_is_refused_an_owner_only_directory() {
        assert!(
            !permits(OWNER_ONLY, 9, 9, 0o1),
            "0700 grants others nothing"
        );
    }

    #[test]
    fn the_group_is_refused_what_only_the_owner_holds() {
        assert!(
            !permits(OWNER_ONLY, 9, 0, 0o2),
            "0700 grants the group nothing"
        );
    }

    #[test]
    fn a_read_grant_is_not_a_write_grant() {
        let file = Entry {
            uid: 0,
            gid: 0,
            mode: 0o644,
        };
        assert!(!permits(file, 9, 9, 0o6), "0644 lets others read only");
    }

    #[test]
    fn one_closed_ancestor_stops_the_reach() {
        let open = Entry {
            uid: 0,
            gid: 0,
            mode: 0o755,
        };
        let mine = Entry {
            uid: 9,
            gid: 9,
            mode: 0o700,
        };
        assert!(
            !reaches(&[open, OWNER_ONLY], mine, 9, 9, Access::Read),
            "a 0700 directory of root above the path"
        );
    }

    #[test]
    fn the_sudo_user_is_not_offered_when_it_cannot() {
        assert_eq!(
            sudo_user_offer(Some("alice"), "nobody", |_| false),
            None,
            "an offer that would be refused too is not made"
        );
    }

    #[test]
    fn root_is_never_offered_as_the_user() {
        assert_eq!(
            sudo_user_offer(Some("root"), "nobody", |_| true),
            None,
            "--user root is --no-priv-drop by another name"
        );
    }

    #[test]
    fn no_sudo_user_means_no_offer() {
        assert_eq!(
            sudo_user_offer(None, "nobody", |_| true),
            None,
            "not started through sudo"
        );
    }

    #[test]
    fn a_refusal_without_an_offer_names_no_user() {
        let text = refusal(
            "--vcon-fetch",
            &need("/root/out", Access::WriteDir),
            "nobody",
            None,
        );
        assert!(
            text.contains("--user USER"),
            "the general form is shown: {text}"
        );
    }

    // ---- edge ----

    #[test]
    fn an_empty_user_is_a_user_and_not_nobody() {
        let asked = Asked {
            flag_user: Some(""),
            ..ROOT
        };
        assert_eq!(
            action(exit("fleet serve"), asked),
            Action::DropTo(""),
            "an empty --user fails at the lookup; it is never replaced by nobody"
        );
    }

    #[test]
    fn an_empty_flag_user_still_wins_over_the_config_user() {
        let asked = Asked {
            flag_user: Some(""),
            config_user: Some("voip"),
            ..ROOT
        };
        assert_eq!(
            action(exit("--vcon-forward"), asked),
            Action::DropTo(""),
            "the command line is not overridden by the file"
        );
    }

    #[test]
    fn a_user_named_root_is_passed_on_as_named() {
        let asked = Asked {
            flag_user: Some("root"),
            ..ROOT
        };
        assert_eq!(
            action(exit("fleet serve"), asked),
            Action::DropTo("root"),
            "the capture run's rule: the named user is the target"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn root_on_macos_with_no_user_keeps_root() {
        assert_eq!(
            action(exit("fleet serve"), ROOT),
            Action::KeepOnMacos,
            "the capture run's rule on macOS"
        );
    }

    #[test]
    fn not_root_with_no_priv_drop_is_unchanged_not_warned() {
        let asked = Asked {
            root: false,
            no_priv_drop: true,
            ..ROOT
        };
        assert_eq!(
            action(exit("fleet serve"), asked),
            Action::Unchanged,
            "nothing is kept that was not held"
        );
    }

    #[test]
    fn every_name_is_in_the_table_once() {
        let mut names: Vec<&str> = rows().map(|row| row.name).collect();
        let all = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all, "a name appears twice");
    }

    #[test]
    fn every_row_has_a_reason_and_a_step() {
        for row in rows() {
            assert!(!row.reason.is_empty(), "{} has no reason", row.name);
            assert!(!row.step.is_empty(), "{} has no step", row.name);
        }
    }

    #[test]
    fn only_listener_and_client_rows_drop_here() {
        for row in rows() {
            let drops = matches!(
                action(
                    row,
                    Asked {
                        flag_user: Some("u"),
                        ..ROOT
                    }
                ),
                Action::DropTo(_)
            );
            assert_eq!(drops, row.plan.drops_here(), "{}", row.name);
        }
    }

    #[test]
    fn the_owner_is_judged_by_the_owner_bits_alone() {
        let odd = Entry {
            uid: 9,
            gid: 9,
            mode: 0o077,
        };
        assert!(
            !permits(odd, 9, 9, 0o4),
            "the kernel reads the owner bits for the owner, even when group and other grant more"
        );
    }

    #[test]
    fn a_group_member_is_judged_by_the_group_bits_alone() {
        let odd = Entry {
            uid: 0,
            gid: 9,
            mode: 0o707,
        };
        assert!(
            !permits(odd, 5, 9, 0o4),
            "the group bits decide for the group, even when other grants more"
        );
    }

    #[test]
    fn file_type_bits_in_the_mode_are_ignored() {
        let dir = Entry {
            uid: 0,
            gid: 0,
            mode: 0o040_755,
        };
        assert!(permits(dir, 9, 9, 0o5), "S_IFDIR does not change the grant");
    }

    #[test]
    fn a_path_with_no_ancestor_is_judged_by_itself() {
        assert!(
            reaches(&[], OWNER_ONLY, 0, 0, Access::WriteDir),
            "the root directory has no directory above it"
        );
    }

    #[test]
    fn the_target_itself_is_not_offered_again() {
        assert_eq!(
            sudo_user_offer(Some("nobody"), "nobody", |_| true),
            None,
            "the run already is that user"
        );
    }

    #[test]
    fn a_sudo_user_a_shell_would_split_is_not_offered() {
        for name in ["a b", "a;b", "$(x)", "", "-x", "a'b"] {
            assert_eq!(
                sudo_user_offer(Some(name), "nobody", |_| true),
                None,
                "{name:?} is not printed into a command"
            );
        }
    }

    #[test]
    fn the_refusal_words_each_access() {
        for (access, words) in [
            (Access::Read, "cannot read "),
            (Access::ReadWrite, "cannot read and write "),
            (Access::WriteDir, "cannot write in "),
            (Access::ReadDir, "cannot read "),
        ] {
            let text = refusal("fleet serve", &need("/p", access), "nobody", None);
            assert!(text.contains(words), "{words:?} not in: {text}");
        }
    }

    #[test]
    fn the_kept_root_warning_names_the_command_and_the_flag() {
        let line = kept_root_warning("fleet serve");
        assert!(
            line.contains("fleet serve") && line.contains("--no-priv-drop"),
            "{line}"
        );
    }

    // ---- `fleet verify`: reads its key files as root, then drops ----

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn success_verify_started_as_root_drops_to_nobody() {
        assert_eq!(
            action(exit("fleet verify"), ROOT),
            Action::DropTo("nobody"),
            "success a root run of `fleet verify` with no --user reads history files as nobody"
        );
    }

    #[test]
    fn success_verify_started_as_root_drops_to_the_flag_user() {
        let asked = Asked {
            flag_user: Some("sipnab-center"),
            ..ROOT
        };
        assert_eq!(
            action(exit("fleet verify"), asked),
            Action::DropTo("sipnab-center"),
            "success --user names the user `fleet verify` reads history files as"
        );
    }

    #[test]
    fn success_verify_with_no_priv_drop_keeps_root_and_warns() {
        let asked = Asked {
            no_priv_drop: true,
            flag_user: Some("sipnab-center"),
            ..ROOT
        };
        assert_eq!(
            action(exit("fleet verify"), asked),
            Action::KeepWarned,
            "success --no-priv-drop keeps root for `fleet verify`, with the warning line"
        );
    }

    #[test]
    fn edge_verify_not_started_as_root_changes_in_nothing() {
        let asked = Asked {
            root: false,
            flag_user: Some("sipnab-center"),
            ..ROOT
        };
        assert_eq!(
            action(exit("fleet verify"), asked),
            Action::Unchanged,
            "edge a `fleet verify` that is not root stays the user it was started as"
        );
    }

    #[test]
    fn edge_the_verify_row_says_what_it_reads_on_each_side_of_the_drop() {
        let row = exit("fleet verify");
        assert!(
            row.plan.drops_here(),
            "edge the plan of `fleet verify` is one that drops: {:?}",
            row.plan
        );
        assert!(
            row.reason.contains("key files as root") && row.reason.contains("history file"),
            "edge the reason names the key files before the drop and the history files after: {}",
            row.reason
        );
    }

    #[test]
    fn success_a_directory_is_read_with_the_read_and_search_bits() {
        let dir = |mode| Entry {
            uid: 7,
            gid: 8,
            mode,
        };
        assert!(
            reaches(&[], dir(0o500), 7, 9, Access::ReadDir),
            "success the owner lists a directory it may read and search"
        );
        assert!(
            reaches(&[], dir(0o050), 6, 8, Access::ReadDir),
            "success a member of the group lists it by the group bits"
        );
        assert!(
            reaches(&[], dir(0o005), 6, 9, Access::ReadDir),
            "success everyone else lists it by the other bits"
        );
    }

    #[test]
    fn failure_a_directory_without_the_search_bit_is_not_read() {
        let leaf = Entry {
            uid: 7,
            gid: 8,
            mode: 0o704,
        };
        assert!(
            !reaches(&[], leaf, 6, 9, Access::ReadDir),
            "failure a directory a user may list and not search is not one it can read files in"
        );
    }

    #[test]
    fn failure_a_directory_without_the_read_bit_is_not_read() {
        let leaf = Entry {
            uid: 7,
            gid: 8,
            mode: 0o701,
        };
        assert!(
            !reaches(&[], leaf, 6, 9, Access::ReadDir),
            "failure a directory a user may search and not list is not one a pass can read"
        );
    }

    #[test]
    fn edge_a_write_grant_is_not_a_read_of_a_directory() {
        let leaf = Entry {
            uid: 7,
            gid: 8,
            mode: 0o702,
        };
        assert!(
            !reaches(&[], leaf, 6, 9, Access::ReadDir),
            "edge the write bit alone lists nothing"
        );
        assert_eq!(
            Access::ReadDir.bits(),
            0o5,
            "edge a directory is read with the read and the search bit, and no other"
        );
    }

    #[test]
    fn failure_the_refusal_of_a_history_store_names_the_three_ways_out() {
        let lack = Need {
            path: PathBuf::from("/var/lib/sipnab/center.store.parquet"),
            what: "the history store of --store",
            access: Access::ReadDir,
        };
        assert_eq!(
            refusal("fleet verify", &lack, "nobody", Some("center")),
            "fleet verify: started as root, this command runs as user 'nobody', and 'nobody' \
             cannot read '/var/lib/sipnab/center.store.parquet' (the history store of --store). \
             Nothing was created. Choose one: chown nobody \
             '/var/lib/sipnab/center.store.parquet'; run it with --user center, who can; or pass \
             --no-priv-drop to keep root",
            "failure the refusal of `fleet verify` is the one a center's start gives"
        );
    }

    type TestError = Box<dyn std::error::Error>;

    #[test]
    fn success_a_read_tree_needs_its_directories_listed_and_its_files_read() -> Result<(), TestError>
    {
        let dir = tempfile::tempdir()?;
        let day = dir.path().join("day");
        std::fs::create_dir(&day)?;
        std::fs::write(day.join("rows"), b"x")?;
        let mut needs = read_tree_needs(dir.path(), "the history store of --store");
        needs.sort_by(|a, b| a.path.cmp(&b.path));
        assert!(
            needs
                .iter()
                .all(|need| need.what == "the history store of --store"),
            "success every need carries the words the refusal prints: {needs:?}"
        );
        let got: Vec<(PathBuf, Access)> = needs.into_iter().map(|n| (n.path, n.access)).collect();
        assert_eq!(
            got,
            [
                (dir.path().to_path_buf(), Access::ReadDir),
                (day.clone(), Access::ReadDir),
                (day.join("rows"), Access::Read),
            ],
            "success every directory to list, every file to read, and nothing to write"
        );
        Ok(())
    }

    #[test]
    fn edge_a_read_tree_that_does_not_exist_has_no_needs() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        assert_eq!(
            read_tree_needs(&dir.path().join("absent"), "--store"),
            [],
            "edge a history directory that is absent is the pass's own refusal, not a lack"
        );
        Ok(())
    }

    #[test]
    fn edge_a_read_tree_does_not_follow_a_symbolic_link() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let tree = dir.path().join("tree");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&tree)?;
        std::fs::create_dir(&outside)?;
        std::fs::write(outside.join("file"), b"x")?;
        std::os::unix::fs::symlink(&outside, tree.join("link"))?;
        let needs = read_tree_needs(&tree, "--store");
        assert_eq!(
            needs
                .iter()
                .map(|n| (n.path.clone(), n.access))
                .collect::<Vec<_>>(),
            [(tree, Access::ReadDir)],
            "edge what a link points to is not part of the tree"
        );
        Ok(())
    }

    #[test]
    fn failure_this_process_lacks_a_directory_it_cannot_list_or_search() -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt as _;
        if !crate::test_prereq::not_root(privilege::is_root()) {
            // Root is granted everything; the lack cannot be shown as root.
            return Ok(());
        }
        let dir = tempfile::tempdir()?;
        let want = |path: &Path| Need {
            path: path.to_path_buf(),
            what: "the history store of --store",
            access: Access::ReadDir,
        };
        assert!(
            holds(&want(dir.path())),
            "failure its own directory is held before it is closed"
        );
        let mut closed = Vec::new();
        for mode in [0o400, 0o100, 0o300] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode))?;
            closed.push((mode, holds(&want(dir.path()))));
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        assert_eq!(
            closed,
            [(0o400, false), (0o100, false), (0o300, false)],
            "failure a directory is lacked without both the read and the search bit"
        );
        Ok(())
    }

    #[test]
    fn edge_a_directory_retention_removed_is_not_a_lack() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let gone = Need {
            path: dir.path().join("date=2026-11-11"),
            what: "the history store of --store",
            access: Access::ReadDir,
        };
        assert!(
            holds(&gone),
            "edge a day removed between the listing and the check is not refused for"
        );
        Ok(())
    }

    #[test]
    fn a_tree_needs_its_directories_written_and_its_files_read() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let day = dir.path().join("day");
        std::fs::create_dir(&day)?;
        std::fs::write(day.join("rows"), b"x")?;
        let mut needs = tree_needs(dir.path(), "--store");
        needs.sort_by(|a, b| a.path.cmp(&b.path));
        let got: Vec<(PathBuf, Access)> = needs.into_iter().map(|n| (n.path, n.access)).collect();
        assert_eq!(
            got,
            [
                (dir.path().to_path_buf(), Access::WriteDir),
                (day.clone(), Access::WriteDir),
                (day.join("rows"), Access::Read),
            ],
            "every directory to write in, every file to read"
        );
        Ok(())
    }

    #[test]
    fn a_tree_that_does_not_exist_has_no_needs() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        assert_eq!(
            tree_needs(&dir.path().join("absent"), "--store"),
            [],
            "the run creates it, as the user it dropped to"
        );
        Ok(())
    }

    #[test]
    fn a_tree_does_not_follow_a_symbolic_link() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let tree = dir.path().join("tree");
        let outside = dir.path().join("outside");
        std::fs::create_dir(&tree)?;
        std::fs::create_dir(&outside)?;
        std::fs::write(outside.join("file"), b"x")?;
        std::os::unix::fs::symlink(&outside, tree.join("link"))?;
        let needs = tree_needs(&tree, "--store");
        assert_eq!(
            needs.iter().map(|n| n.path.clone()).collect::<Vec<_>>(),
            [tree],
            "what a link points to is not part of the tree"
        );
        Ok(())
    }

    #[test]
    fn a_directory_that_exists_is_its_own_need() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        assert_eq!(
            creatable_dir(dir.path(), "--vcon-fetch-out"),
            Need {
                path: dir.path().to_path_buf(),
                what: "--vcon-fetch-out",
                access: Access::WriteDir,
            },
            "an existing output directory must be writable itself"
        );
        Ok(())
    }

    #[test]
    fn a_directory_to_be_made_needs_the_nearest_one_above_it() -> Result<(), TestError> {
        let dir = tempfile::tempdir()?;
        let need = creatable_dir(&dir.path().join("a").join("b"), "--vcon-fetch-out");
        assert_eq!(
            need.path,
            dir.path(),
            "the run makes `a/b` in the nearest directory that exists"
        );
        Ok(())
    }

    #[test]
    fn a_relative_directory_to_be_made_needs_the_current_one() {
        let need = creatable_dir(Path::new("sipnab-no-such-directory-here"), "--out");
        assert_eq!(
            need.path,
            Path::new("."),
            "a bare name is made in the current directory"
        );
    }

    #[test]
    fn this_process_holds_what_it_made_and_lacks_what_it_closed() -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt as _;
        if !crate::test_prereq::not_root(privilege::is_root()) {
            // Root is granted everything; the lack cannot be shown as root.
            return Ok(());
        }
        let dir = tempfile::tempdir()?;
        let file = dir.path().join("file");
        std::fs::write(&file, b"x")?;
        let want = |path: &Path, access| Need {
            path: path.to_path_buf(),
            what: "--store",
            access,
        };
        assert!(
            holds(&want(dir.path(), Access::WriteDir)),
            "its own directory"
        );
        assert!(holds(&want(&file, Access::ReadWrite)), "its own file");
        assert!(
            holds(&want(&dir.path().join("absent"), Access::ReadWrite)),
            "a file that does not exist yet is created, not lacked"
        );
        assert!(
            !holds(&want(&dir.path().join("absent"), Access::WriteDir)),
            "a directory that does not exist cannot be written in"
        );
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o400))?;
        assert!(
            !holds(&want(&file, Access::ReadWrite)),
            "a read-only file is not read and write"
        );
        assert!(holds(&want(&file, Access::Read)), "and is still read");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500))?;
        let closed = !holds(&want(dir.path(), Access::WriteDir));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        assert!(closed, "a directory without the write bit");
        Ok(())
    }

    #[test]
    fn the_caller_is_judged_by_the_modes_on_the_whole_path() -> Result<(), TestError> {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir()?;
        let want = Need {
            path: dir.path().to_path_buf(),
            what: "--store",
            access: Access::WriteDir,
        };
        assert!(
            !user_can("sipnab-no-such-user-here", &want),
            "a user that does not exist can do nothing"
        );
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        let owner = {
            use std::os::unix::fs::MetadataExt as _;
            std::fs::metadata(dir.path())?.uid()
        };
        if owner != 0 {
            assert!(
                !user_can("root", &want),
                "by the mode bits alone, root is a stranger to a 0700 directory of another user"
            );
        }
        Ok(())
    }
}
