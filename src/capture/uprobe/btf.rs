// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reading struct member offsets out of the running kernel's BTF.
//!
//! BTF is the **BPF Type Format**: the kernel's description of its own types —
//! every struct, its members, and the offset of each one.
//!
//! The BPF backend has to read addresses out of `struct sock`, and where those
//! addresses sit differs between kernels. Three ways to deal with that, and two
//! of them are wrong:
//!
//! - **Compile the offsets in.** Correct on the kernel it was built against and
//!   silently wrong on every other one — reading whatever happens to live at
//!   that offset and reporting it as an IP address. The failure has no symptom
//!   except wrong answers.
//! - **Ask CO-RE to relocate them.** The right answer in principle, but the
//!   `aya-ebpf` this builds against ships no CO-RE read helpers.
//! - **Look them up at load time in the kernel's own BTF**, which is what this
//!   module does. Same portability CO-RE gives, resolved in userspace.
//!
//! `aya` cannot do the lookup for us: it parses BTF, but `Struct::members` is
//! `pub(crate)`, so nothing outside the crate can walk a struct. The format is
//! small and stable enough to read directly, and doing so adds no dependency to
//! a project whose whole pitch is one binary.
//!
//! # What is deliberately not here
//!
//! No relocation, no type graph, no validation beyond what the walk needs. This
//! answers exactly one question — *at what byte offset does member X of struct
//! Y live* — and refuses rather than guessing when it cannot.

use std::collections::HashMap;

/// `/sys/kernel/btf/vmlinux`, where a BTF-enabled kernel publishes its types.
pub const VMLINUX_BTF: &str = "/sys/kernel/btf/vmlinux";

/// BTF magic, little-endian. A big-endian kernel writes it byte-swapped, which
/// is how the endianness is detected rather than assumed.
const BTF_MAGIC: u16 = 0xeb9f;

/// Kinds this walk understands well enough to skip or descend into.
mod kind {
    /// `BTF_KIND_INT`, four bytes of trailing encoding data.
    pub const INT: u32 = 1;
    /// `BTF_KIND_ARRAY`, followed by one `btf_array`.
    pub const ARRAY: u32 = 3;
    /// `BTF_KIND_STRUCT`, followed by `vlen` members. Descended into.
    pub const STRUCT: u32 = 4;
    /// `BTF_KIND_UNION`, same shape as a struct and searched the same way —
    /// the ports live inside an anonymous one.
    pub const UNION: u32 = 5;
    /// `BTF_KIND_ENUM`, followed by `vlen` 8-byte entries.
    pub const ENUM: u32 = 6;
    /// `BTF_KIND_FUNC_PROTO`, followed by `vlen` parameters.
    pub const FUNC_PROTO: u32 = 13;
    /// `BTF_KIND_VAR`, four bytes of linkage.
    pub const VAR: u32 = 14;
    /// `BTF_KIND_DATASEC`, followed by `vlen` variable entries.
    pub const DATASEC: u32 = 15;
    /// `BTF_KIND_DECL_TAG`, four bytes naming a component.
    pub const DECL_TAG: u32 = 17;
    /// `BTF_KIND_ENUM64`, followed by `vlen` 12-byte entries.
    pub const ENUM64: u32 = 19;
}

/// Why a BTF lookup could not answer.
#[derive(Debug, PartialEq, Eq)]
pub enum BtfError {
    /// The file is not there. On a kernel built without `CONFIG_DEBUG_INFO_BTF`
    /// it never will be, and that is a property of the machine rather than a
    /// fault — the caller falls back to the tracefs backend.
    Absent,
    /// The file is there but is not BTF, or is truncated.
    Malformed(&'static str),
    /// The type walk completed and the struct is simply not in this kernel.
    NoSuchType(String),
    /// The struct exists but has no member by that name, which usually means a
    /// kernel that renamed or removed it.
    NoSuchMember(String),
}

impl std::fmt::Display for BtfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => write!(
                f,
                "{VMLINUX_BTF} is not present, so this kernel was built without \
                 CONFIG_DEBUG_INFO_BTF"
            ),
            Self::Malformed(why) => write!(f, "{VMLINUX_BTF} is not usable BTF: {why}"),
            Self::NoSuchType(n) => write!(f, "this kernel's BTF has no struct named {n}"),
            Self::NoSuchMember(n) => write!(f, "no member named {n}"),
        }
    }
}

impl std::error::Error for BtfError {}

/// One parsed BTF blob, indexed enough to answer member-offset questions.
pub struct Btf {
    /// Raw type section.
    types: Vec<u8>,
    /// Raw string section.
    strings: Vec<u8>,
    /// Byte order the blob was written in.
    little_endian: bool,
    /// Type id → byte offset into `types`, built by one linear walk.
    index: Vec<usize>,
    /// Struct/union name → type id, for the lookups this module answers.
    by_name: HashMap<String, u32>,
}

impl Btf {
    /// Read and index the running kernel's BTF.
    ///
    /// # Errors
    ///
    /// [`BtfError::Absent`] when the kernel published none — the ordinary
    /// outcome on a kernel without `CONFIG_DEBUG_INFO_BTF`, and the caller's
    /// signal to use the tracefs backend instead.
    pub fn from_sys_fs() -> Result<Self, BtfError> {
        Self::from_path(std::path::Path::new(VMLINUX_BTF))
    }

    /// Read and index a BTF blob from a file.
    ///
    /// # Errors
    ///
    /// As [`Self::from_sys_fs`], plus [`BtfError::Malformed`] for a file that
    /// is present but not BTF.
    pub fn from_path(path: &std::path::Path) -> Result<Self, BtfError> {
        let raw = std::fs::read(path).map_err(|_| BtfError::Absent)?;
        Self::parse(&raw)
    }

    /// Parse a BTF blob.
    ///
    /// # Errors
    ///
    /// [`BtfError::Malformed`] with the specific reason, never a generic
    /// failure: a truncated blob and a non-BTF file need different fixes.
    #[allow(clippy::missing_panics_doc)]
    pub fn parse(raw: &[u8]) -> Result<Self, BtfError> {
        if raw.len() < 24 {
            return Err(BtfError::Malformed("shorter than a BTF header"));
        }
        let le_magic = u16::from_le_bytes([raw[0], raw[1]]);
        let little_endian = if le_magic == BTF_MAGIC {
            true
        } else if u16::from_be_bytes([raw[0], raw[1]]) == BTF_MAGIC {
            false
        } else {
            return Err(BtfError::Malformed("bad magic"));
        };

        let rd32 = |at: usize| -> u32 {
            let b = [raw[at], raw[at + 1], raw[at + 2], raw[at + 3]];
            if little_endian {
                u32::from_le_bytes(b)
            } else {
                u32::from_be_bytes(b)
            }
        };
        // magic(2) version(1) flags(1) hdr_len(4) then four section words.
        let hdr_len = rd32(4) as usize;
        let type_off = rd32(8) as usize;
        let type_len = rd32(12) as usize;
        let str_off = rd32(16) as usize;
        let str_len = rd32(20) as usize;

        let type_start = hdr_len
            .checked_add(type_off)
            .ok_or(BtfError::Malformed("type offset overflows"))?;
        let str_start = hdr_len
            .checked_add(str_off)
            .ok_or(BtfError::Malformed("string offset overflows"))?;
        let type_end = type_start
            .checked_add(type_len)
            .ok_or(BtfError::Malformed("type length overflows"))?;
        let str_end = str_start
            .checked_add(str_len)
            .ok_or(BtfError::Malformed("string length overflows"))?;
        if type_end > raw.len() || str_end > raw.len() {
            return Err(BtfError::Malformed("sections extend past the file"));
        }

        let mut this = Self {
            types: raw[type_start..type_end].to_vec(),
            strings: raw[str_start..str_end].to_vec(),
            little_endian,
            // Type id 0 is the void type and has no entry, so the index starts
            // with a placeholder to keep ids and positions aligned.
            index: vec![usize::MAX],
            by_name: HashMap::new(),
        };
        this.build_index()?;
        Ok(this)
    }

    /// Read a `u32` from the type section.
    fn t32(&self, at: usize) -> Option<u32> {
        let b = self.types.get(at..at + 4)?;
        let b = [b[0], b[1], b[2], b[3]];
        Some(if self.little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    /// The NUL-terminated string at `off` in the string section.
    fn string(&self, off: u32) -> &str {
        let off = off as usize;
        let Some(rest) = self.strings.get(off..) else {
            return "";
        };
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        std::str::from_utf8(&rest[..end]).unwrap_or("")
    }

    /// How many bytes of trailing data a type of this kind carries.
    ///
    /// Getting this wrong desynchronizes the whole walk, so every kind the
    /// format defines is listed. An unknown kind returns `None` rather than a
    /// guess: continuing past one would index every later type incorrectly and
    /// still produce plausible answers.
    fn trailing_len(kind: u32, vlen: u32) -> Option<usize> {
        let vlen = vlen as usize;
        Some(match kind {
            kind::INT | kind::VAR | kind::DECL_TAG => 4,
            kind::ARRAY => 12,
            kind::STRUCT | kind::UNION | kind::DATASEC => vlen * 12,
            kind::ENUM | kind::FUNC_PROTO => vlen * 8,
            kind::ENUM64 => vlen * 12,
            // PTR, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FLOAT,
            // TYPE_TAG: the common header is the whole type.
            2 | 7..=12 | 16 | 18 => 0,
            _ => return None,
        })
    }

    /// Walk the type section once, recording where each type starts.
    fn build_index(&mut self) -> Result<(), BtfError> {
        let mut at = 0usize;
        let mut id = 1u32;
        while at < self.types.len() {
            let name_off = self
                .t32(at)
                .ok_or(BtfError::Malformed("type header past the section"))?;
            let info = self
                .t32(at + 4)
                .ok_or(BtfError::Malformed("type info past the section"))?;
            let vlen = info & 0xffff;
            let kind = (info >> 24) & 0x1f;
            let trailing = Self::trailing_len(kind, vlen)
                .ok_or(BtfError::Malformed("unknown BTF kind; refusing to guess"))?;

            self.index.push(at);
            if kind == kind::STRUCT || kind == kind::UNION {
                let name = self.string(name_off).to_string();
                if !name.is_empty() {
                    // First definition wins. A kernel can carry several types
                    // with one name across modules; the vmlinux one comes first.
                    self.by_name.entry(name).or_insert(id);
                }
            }

            at = at
                .checked_add(12 + trailing)
                .ok_or(BtfError::Malformed("type size overflows"))?;
            id += 1;
        }
        Ok(())
    }

    /// Byte offset of `member` within `struct`, following anonymous members.
    ///
    /// Anonymous members matter here rather than being a nicety: the addresses
    /// live in `sock.__sk_common`, which is a named member of type
    /// `struct sock_common`, and the ports are reached through anonymous unions
    /// inside it.
    ///
    /// # Errors
    ///
    /// [`BtfError::NoSuchType`] or [`BtfError::NoSuchMember`], so a caller can
    /// say which half of the question failed.
    pub fn member_offset(&self, struct_name: &str, member: &str) -> Result<u32, BtfError> {
        let id = *self
            .by_name
            .get(struct_name)
            .ok_or_else(|| BtfError::NoSuchType(struct_name.to_string()))?;
        self.find_member(id, member, 0, 0)
            .ok_or_else(|| BtfError::NoSuchMember(member.to_string()))
    }

    /// Search `type_id`'s members for `want`, descending into nested and
    /// anonymous aggregates.
    ///
    /// `depth` bounds the descent. A BTF blob with a cycle would otherwise
    /// recurse forever, and this reads a file the kernel exposes rather than
    /// one sipnab produced.
    fn find_member(&self, type_id: u32, want: &str, base_bits: u32, depth: u32) -> Option<u32> {
        if depth > 8 {
            return None;
        }
        let at = *self.index.get(type_id as usize)?;
        if at == usize::MAX {
            return None;
        }
        let info = self.t32(at + 4)?;
        let vlen = info & 0xffff;
        let kind = (info >> 24) & 0x1f;
        let kind_flag = (info >> 31) & 1;
        if kind != kind::STRUCT && kind != kind::UNION {
            return None;
        }

        for i in 0..vlen as usize {
            let m = at + 12 + i * 12;
            let name_off = self.t32(m)?;
            let m_type = self.t32(m + 4)?;
            let raw_off = self.t32(m + 8)?;
            // With `kind_flag` set the word packs a bitfield size above a
            // 24-bit offset; without it the whole word is the bit offset.
            let bit_off = if kind_flag == 1 {
                raw_off & 0x00ff_ffff
            } else {
                raw_off
            };
            let here = base_bits + bit_off;
            let name = self.string(name_off);

            if name == want {
                return Some(here / 8);
            }
            // An anonymous member's fields belong to the enclosing struct, so
            // the search continues inside it at the same nesting level.
            if name.is_empty()
                && let Some(found) = self.find_member(self.strip(m_type, 0), want, here, depth + 1)
            {
                return Some(found);
            }
        }
        None
    }

    /// Follow typedef/const/volatile/restrict wrappers to the type underneath.
    fn strip(&self, mut type_id: u32, depth: u32) -> u32 {
        if depth > 8 {
            return type_id;
        }
        let Some(&at) = self.index.get(type_id as usize) else {
            return type_id;
        };
        if at == usize::MAX {
            return type_id;
        }
        let Some(info) = self.t32(at + 4) else {
            return type_id;
        };
        let kind = (info >> 24) & 0x1f;
        // TYPEDEF, VOLATILE, CONST, RESTRICT all name a type in the size slot.
        if matches!(kind, 8..=11)
            && let Some(inner) = self.t32(at + 8)
        {
            type_id = self.strip(inner, depth + 1);
        }
        type_id
    }

    /// The member offsets the BPF program needs, resolved together.
    ///
    /// All or nothing on purpose: a partial set would leave some offsets zero,
    /// and zero is a legal offset. The program would read the start of the
    /// struct and report it as an address.
    ///
    /// # Errors
    ///
    /// The first member that could not be resolved, named.
    pub fn sock_offsets(&self) -> Result<sipnab_bpf_types::SockOffsets, BtfError> {
        // Every one of these lives in `struct sock_common`, which `struct sock`
        // embeds as `__sk_common`. Looking them up in `sock_common` directly
        // avoids depending on that member's own name, which has changed before.
        let g = |m: &str| self.member_offset("sock_common", m);
        let common = self.member_offset("sock", "__sk_common")?;

        Ok(sipnab_bpf_types::SockOffsets {
            family: common + g("skc_family")?,
            saddr4: common + g("skc_rcv_saddr")?,
            daddr4: common + g("skc_daddr")?,
            saddr6: common + g("skc_v6_rcv_saddr")?,
            daddr6: common + g("skc_v6_daddr")?,
            sport: common + g("skc_num")?,
            dport: common + g("skc_dport")?,
            valid: 1,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a BTF blob by hand, so the walk is tested against bytes rather
    /// than against whatever kernel happens to be running the tests. thor-02
    /// has no BTF at all, so a test that needed a real one would be skipped
    /// exactly where it matters.
    struct BtfBuilder {
        types: Vec<u8>,
        strings: Vec<u8>,
    }

    impl BtfBuilder {
        fn new() -> Self {
            Self {
                types: Vec::new(),
                // The string section always starts with the empty string.
                strings: vec![0],
            }
        }

        fn intern(&mut self, s: &str) -> u32 {
            let at = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            at
        }

        /// Add an INT type (4 bytes of trailing data).
        fn int(&mut self, name: &str, size: u32) -> u32 {
            let n = self.intern(name);
            self.types.extend_from_slice(&n.to_le_bytes());
            // kind INT in bits 24..28, vlen 0 — spelled out so the shape of
            // the info word stays readable next to the other builders.
            let info = kind::INT << 24;
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&size.to_le_bytes());
            self.types.extend_from_slice(&0u32.to_le_bytes());
            self.next_id()
        }

        /// Add a STRUCT with `(name, type_id, bit_offset)` members.
        fn strukt(&mut self, name: &str, size: u32, members: &[(&str, u32, u32)]) -> u32 {
            let n = self.intern(name);
            let names: Vec<u32> = members.iter().map(|(m, _, _)| self.intern(m)).collect();
            self.types.extend_from_slice(&n.to_le_bytes());
            let info = (4u32 << 24) | (members.len() as u32);
            self.types.extend_from_slice(&info.to_le_bytes());
            self.types.extend_from_slice(&size.to_le_bytes());
            for (i, (_, ty, off)) in members.iter().enumerate() {
                self.types.extend_from_slice(&names[i].to_le_bytes());
                self.types.extend_from_slice(&ty.to_le_bytes());
                self.types.extend_from_slice(&off.to_le_bytes());
            }
            self.next_id()
        }

        /// Ids are positions in the type array, counted as it is built.
        fn next_id(&mut self) -> u32 {
            let mut at = 0usize;
            let mut id = 0u32;
            while at < self.types.len() {
                let info = u32::from_le_bytes(self.types[at + 4..at + 8].try_into().unwrap());
                let vlen = info & 0xffff;
                let kind = (info >> 24) & 0x1f;
                at += 12 + Btf::trailing_len(kind, vlen).unwrap();
                id += 1;
            }
            id
        }

        fn build(&self) -> Vec<u8> {
            let mut out = Vec::new();
            out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
            out.push(1); // version
            out.push(0); // flags
            out.extend_from_slice(&24u32.to_le_bytes()); // hdr_len
            out.extend_from_slice(&0u32.to_le_bytes()); // type_off
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes());
            out.extend_from_slice(&(self.types.len() as u32).to_le_bytes()); // str_off
            out.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
            out.extend_from_slice(&self.types);
            out.extend_from_slice(&self.strings);
            out
        }
    }

    /// A miniature `sock` / `sock_common` pair with the members that matter.
    fn kernel_like() -> Vec<u8> {
        let mut b = BtfBuilder::new();
        let u16t = b.int("short unsigned int", 2);
        let u32t = b.int("unsigned int", 4);
        let addr6 = b.int("in6_addr", 16);
        // Bit offsets, as BTF records them.
        let common = b.strukt(
            "sock_common",
            64,
            &[
                ("skc_daddr", u32t, 0),
                ("skc_rcv_saddr", u32t, 32),
                ("skc_dport", u16t, 64),
                ("skc_num", u16t, 80),
                ("skc_family", u16t, 96),
                ("skc_v6_daddr", addr6, 128),
                ("skc_v6_rcv_saddr", addr6, 256),
            ],
        );
        let _sock = b.strukt("sock", 760, &[("__sk_common", common, 0)]);
        b.build()
    }

    #[test]
    fn member_offsets_come_out_in_bytes() {
        let btf = Btf::parse(&kernel_like()).expect("hand-built BTF parses");
        assert_eq!(btf.member_offset("sock_common", "skc_daddr"), Ok(0));
        assert_eq!(btf.member_offset("sock_common", "skc_rcv_saddr"), Ok(4));
        assert_eq!(btf.member_offset("sock_common", "skc_dport"), Ok(8));
        assert_eq!(btf.member_offset("sock_common", "skc_family"), Ok(12));
        assert_eq!(
            btf.member_offset("sock_common", "skc_v6_daddr"),
            Ok(16),
            "bit offsets are divided by eight, not used raw"
        );
    }

    /// The whole set, assembled the way the loader will use it.
    #[test]
    fn the_sock_offsets_are_resolved_together() {
        let btf = Btf::parse(&kernel_like()).expect("parses");
        let off = btf.sock_offsets().expect("every member present");
        assert_eq!(off.valid, 1);
        assert_eq!(off.daddr4, 0);
        assert_eq!(off.saddr4, 4);
        assert_eq!(off.dport, 8);
        assert_eq!(off.sport, 10);
        assert_eq!(off.family, 12);
        assert_eq!(off.daddr6, 16);
        assert_eq!(off.saddr6, 32);
    }

    /// **All or nothing.** A partial set would leave offsets zero, and zero is
    /// a legal offset — the program would read the start of the struct and
    /// report it as an address.
    #[test]
    fn a_missing_member_fails_the_whole_set_rather_than_zeroing_one() {
        let mut b = BtfBuilder::new();
        let u32t = b.int("unsigned int", 4);
        let common = b.strukt("sock_common", 8, &[("skc_daddr", u32t, 0)]);
        let _sock = b.strukt("sock", 8, &[("__sk_common", common, 0)]);
        let btf = Btf::parse(&b.build()).expect("parses");

        let err = btf.sock_offsets().expect_err("skc_family is missing");
        assert!(
            matches!(err, BtfError::NoSuchMember(ref m) if m.contains("skc_")),
            "the failure must name the member: {err:?}"
        );
    }

    /// A kernel without the struct at all is a clear refusal, not a zero.
    #[test]
    fn a_kernel_without_the_struct_says_which_type_is_missing() {
        let mut b = BtfBuilder::new();
        let _ = b.int("unsigned int", 4);
        let btf = Btf::parse(&b.build()).expect("parses");
        assert_eq!(
            btf.member_offset("sock", "__sk_common"),
            Err(BtfError::NoSuchType("sock".to_string()))
        );
    }

    /// Anonymous members are transparent: their fields belong to the parent.
    #[test]
    fn an_anonymous_member_is_searched_at_the_parent_offset() {
        let mut b = BtfBuilder::new();
        let u16t = b.int("short unsigned int", 2);
        let inner = b.strukt("inner", 4, &[("skc_num", u16t, 0), ("skc_dport", u16t, 16)]);
        // The anonymous member sits 64 bits in; its fields must land at 8 and 10.
        let outer = b.strukt("sock_common", 16, &[("", inner, 64)]);
        assert!(outer > 0);
        let btf = Btf::parse(&b.build()).expect("parses");
        assert_eq!(btf.member_offset("sock_common", "skc_num"), Ok(8));
        assert_eq!(btf.member_offset("sock_common", "skc_dport"), Ok(10));
    }

    #[test]
    fn a_file_that_is_not_btf_is_refused_with_the_reason() {
        // Long enough to reach the magic check — a shorter one is refused
        // for being short, which is a different (and also correct) answer.
        assert_eq!(
            Btf::parse(b"not btf at all, really -- not even close").err(),
            Some(BtfError::Malformed("bad magic"))
        );
        assert_eq!(
            Btf::parse(&[0u8; 4]).err(),
            Some(BtfError::Malformed("shorter than a BTF header"))
        );
    }

    /// A blob claiming sections past its own end must not be walked.
    #[test]
    fn a_truncated_blob_is_refused_rather_than_read_past() {
        let mut raw = kernel_like();
        raw.truncate(raw.len() - 8);
        // Header still claims the original lengths.
        assert_eq!(
            Btf::parse(&raw).err(),
            Some(BtfError::Malformed("sections extend past the file"))
        );
    }

    /// The real kernel, when there is one. thor-02 has no BTF, so this asserts
    /// only that the two outcomes are the ones that exist: a full set, or the
    /// specific "no BTF here" refusal that sends the caller to tracefs.
    #[test]
    fn the_running_kernel_either_answers_fully_or_says_it_has_no_btf() {
        match Btf::from_sys_fs() {
            Ok(btf) => {
                let off = btf.sock_offsets().expect("a BTF kernel must resolve sock");
                assert_eq!(off.valid, 1);
                assert!(
                    off.family > 0 && off.dport > 0,
                    "offset zero for a member that is not first means the walk \
                     silently failed: {off:?}"
                );
            }
            Err(e) => assert_eq!(
                e,
                BtfError::Absent,
                "a present-but-unreadable BTF is a real failure, not a fallback"
            ),
        }
    }
}
