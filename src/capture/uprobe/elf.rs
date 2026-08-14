//! Finding the file offset of a function in a shared library.
//!
//! A uprobe is placed at an offset **into the file**, not at a virtual address,
//! and the two are not the same number. A symbol table records `st_value`, a
//! virtual address; the `PT_LOAD` segment containing it maps file offset
//! `p_offset` at virtual address `p_vaddr`, and those differ in real libraries.
//! Measured on this host's `libssl.so.3`: the second `LOAD` maps `p_offset`
//! `0x0a6b68` at `p_vaddr` `0x0b6b68`, a 64 KiB shift. A probe placed at
//! `st_value` for a symbol in that segment lands 64 KiB into the wrong code and
//! reports whatever it finds there as a SIP message.
//!
//! Everything here is a pure function of bytes, so the arithmetic that decides
//! where a probe lands is testable without a kernel, a library, or root.

/// ELF identification bytes and the little-endian 64-bit class this supports.
const MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
/// `EI_CLASS` value for 64-bit objects.
const CLASS64: u8 = 2;
/// `EI_DATA` value for little-endian objects.
const LSB: u8 = 1;
/// `sh_type` for a dynamic symbol table.
const SHT_DYNSYM: u32 = 11;
/// `p_type` for a loadable segment.
const PT_LOAD: u32 = 1;
/// Low nibble of `st_info` marking a function.
const STT_FUNC: u8 = 2;

/// Why a symbol could not be turned into a probe offset.
#[derive(Debug, PartialEq, Eq)]
pub enum ElfError {
    /// Not an ELF file at all.
    NotElf,
    /// A 32-bit or big-endian object, which sipnab's probe targets never are.
    Unsupported,
    /// The file is shorter than its own headers claim.
    Truncated,
    /// The symbol is absent, or present and not a function.
    NoSuchSymbol(String),
    /// The symbol's address is in no loadable segment, so it has no file offset.
    NotMapped(String),
}

impl std::fmt::Display for ElfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotElf => write!(f, "not an ELF object"),
            Self::Unsupported => {
                write!(f, "only little-endian 64-bit ELF objects are supported")
            }
            Self::Truncated => write!(f, "the object is shorter than its headers claim"),
            Self::NoSuchSymbol(n) => write!(
                f,
                "'{n}' is not an exported function here. A probe cannot be \
                 placed on a symbol that is absent, and guessing an offset \
                 would read unrelated code"
            ),
            Self::NotMapped(n) => write!(
                f,
                "'{n}' has an address in no PT_LOAD segment, so it has no file \
                 offset to place a probe at"
            ),
        }
    }
}

impl std::error::Error for ElfError {}

/// Read a little-endian `u16` at `at`.
fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// Read a little-endian `u32` at `at`.
fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Read a little-endian `u64` at `at`.
fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Translate a virtual address to a file offset using the loadable segments.
///
/// This is the step that cannot be skipped: `p_vaddr` and `p_offset` differ in
/// real libraries, so `st_value` is not a file offset even though it often
/// looks like one in the first segment.
fn vaddr_to_file_offset(elf: &[u8], vaddr: u64) -> Option<u64> {
    let e_phoff = u64_at(elf, 0x20)? as usize;
    let e_phentsize = u16_at(elf, 0x36)? as usize;
    let e_phnum = u16_at(elf, 0x38)? as usize;

    for i in 0..e_phnum {
        let ph = e_phoff.checked_add(i.checked_mul(e_phentsize)?)?;
        if u32_at(elf, ph)? != PT_LOAD {
            continue;
        }
        let p_offset = u64_at(elf, ph + 0x08)?;
        let p_vaddr = u64_at(elf, ph + 0x10)?;
        let p_filesz = u64_at(elf, ph + 0x20)?;
        if vaddr >= p_vaddr && vaddr < p_vaddr.checked_add(p_filesz)? {
            return Some(vaddr - p_vaddr + p_offset);
        }
    }
    None
}

/// The file offset of an exported function, for placing a uprobe.
///
/// Version suffixes are stripped, so `SSL_write` matches the
/// `SSL_write@@OPENSSL_3.0.0` that a real `libssl` exports.
///
/// # Errors
///
/// Every failure is named rather than defaulted. There is no sensible fallback
/// offset: a wrong one silently probes unrelated code.
pub fn function_file_offset(elf: &[u8], want: &str) -> Result<u64, ElfError> {
    if elf.len() < 0x40 || elf.get(..4) != Some(&MAGIC) {
        return Err(ElfError::NotElf);
    }
    if elf.get(4) != Some(&CLASS64) || elf.get(5) != Some(&LSB) {
        return Err(ElfError::Unsupported);
    }

    let e_shoff = u64_at(elf, 0x28).ok_or(ElfError::Truncated)? as usize;
    let e_shentsize = u16_at(elf, 0x3a).ok_or(ElfError::Truncated)? as usize;
    let e_shnum = u16_at(elf, 0x3c).ok_or(ElfError::Truncated)? as usize;

    for i in 0..e_shnum {
        let sh = e_shoff
            .checked_add(i.checked_mul(e_shentsize).ok_or(ElfError::Truncated)?)
            .ok_or(ElfError::Truncated)?;
        if u32_at(elf, sh + 4).ok_or(ElfError::Truncated)? != SHT_DYNSYM {
            continue;
        }
        let sym_off = u64_at(elf, sh + 0x18).ok_or(ElfError::Truncated)? as usize;
        let sym_size = u64_at(elf, sh + 0x20).ok_or(ElfError::Truncated)? as usize;
        let entsize = u64_at(elf, sh + 0x38).ok_or(ElfError::Truncated)? as usize;
        // The string table this symbol table names, rather than any that looks
        // plausible: reading names out of the wrong table yields a symbol that
        // matches by accident.
        let link = u32_at(elf, sh + 0x28).ok_or(ElfError::Truncated)? as usize;
        let str_sh = e_shoff
            .checked_add(link.checked_mul(e_shentsize).ok_or(ElfError::Truncated)?)
            .ok_or(ElfError::Truncated)?;
        let str_off = u64_at(elf, str_sh + 0x18).ok_or(ElfError::Truncated)? as usize;

        if entsize == 0 {
            return Err(ElfError::Truncated);
        }
        for s in 0..(sym_size / entsize) {
            let sym = sym_off + s * entsize;
            let st_name = u32_at(elf, sym).ok_or(ElfError::Truncated)? as usize;
            let st_info = *elf.get(sym + 4).ok_or(ElfError::Truncated)?;
            let st_value = u64_at(elf, sym + 8).ok_or(ElfError::Truncated)?;
            if st_info & 0xf != STT_FUNC || st_value == 0 {
                continue;
            }
            let name = c_str_at(elf, str_off + st_name).ok_or(ElfError::Truncated)?;
            // `SSL_write@@OPENSSL_3.0.0` is the same function as `SSL_write`.
            let bare = name.split('@').next().unwrap_or(name);
            if bare == want {
                return vaddr_to_file_offset(elf, st_value)
                    .ok_or_else(|| ElfError::NotMapped(want.to_string()));
            }
        }
    }
    Err(ElfError::NoSuchSymbol(want.to_string()))
}

/// Read a NUL-terminated name at `at`.
fn c_str_at(b: &[u8], at: usize) -> Option<&str> {
    let rest = b.get(at..)?;
    let end = rest.iter().position(|&c| c == 0)?;
    std::str::from_utf8(&rest[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ELF64 with two `PT_LOAD` segments whose `p_vaddr` and
    /// `p_offset` DIFFER, and one dynamic function symbol in the second.
    ///
    /// The shift is the whole point: it is what makes `st_value` the wrong
    /// answer, and this host's real `libssl` has exactly this shape.
    fn elf_with_symbol(name: &str, st_value: u64) -> Vec<u8> {
        let mut b = vec![0u8; 0x400];
        b[..4].copy_from_slice(&MAGIC);
        b[4] = CLASS64;
        b[5] = LSB;

        let phoff = 0x40usize;
        let shoff = 0x100usize;
        b[0x20..0x28].copy_from_slice(&(phoff as u64).to_le_bytes());
        b[0x28..0x30].copy_from_slice(&(shoff as u64).to_le_bytes());
        b[0x36..0x38].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes()); // e_phnum
        b[0x3a..0x3c].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
        b[0x3c..0x3e].copy_from_slice(&2u16.to_le_bytes()); // e_shnum

        // LOAD #0: vaddr == offset == 0, the segment that hides the bug.
        let p0 = phoff;
        b[p0..p0 + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        b[p0 + 0x20..p0 + 0x28].copy_from_slice(&0x1000u64.to_le_bytes()); // p_filesz
        // LOAD #1: p_offset 0x2000 maps at p_vaddr 0x12000 — a 0x10000 shift.
        let p1 = phoff + 56;
        b[p1..p1 + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        b[p1 + 0x08..p1 + 0x10].copy_from_slice(&0x2000u64.to_le_bytes()); // p_offset
        b[p1 + 0x10..p1 + 0x18].copy_from_slice(&0x12000u64.to_le_bytes()); // p_vaddr
        b[p1 + 0x20..p1 + 0x28].copy_from_slice(&0x1000u64.to_le_bytes()); // p_filesz

        // Section 0: .dynstr at 0x300. Section 1: .dynsym at 0x200.
        let strtab = 0x300usize;
        let symtab = 0x200usize;
        let s0 = shoff;
        b[s0 + 4..s0 + 8].copy_from_slice(&3u32.to_le_bytes()); // SHT_STRTAB
        b[s0 + 0x18..s0 + 0x20].copy_from_slice(&(strtab as u64).to_le_bytes());
        let s1 = shoff + 64;
        b[s1 + 4..s1 + 8].copy_from_slice(&SHT_DYNSYM.to_le_bytes());
        b[s1 + 0x18..s1 + 0x20].copy_from_slice(&(symtab as u64).to_le_bytes());
        b[s1 + 0x20..s1 + 0x28].copy_from_slice(&48u64.to_le_bytes()); // sh_size: 2 syms
        b[s1 + 0x28..s1 + 0x2c].copy_from_slice(&0u32.to_le_bytes()); // sh_link -> section 0
        b[s1 + 0x38..s1 + 0x40].copy_from_slice(&24u64.to_le_bytes()); // sh_entsize

        // Symbol 0 is the null entry; symbol 1 is ours.
        let sym1 = symtab + 24;
        b[sym1..sym1 + 4].copy_from_slice(&1u32.to_le_bytes()); // st_name -> offset 1
        b[sym1 + 4] = STT_FUNC;
        b[sym1 + 8..sym1 + 16].copy_from_slice(&st_value.to_le_bytes());

        b[strtab] = 0;
        b[strtab + 1..strtab + 1 + name.len()].copy_from_slice(name.as_bytes());
        b
    }

    /// The conversion this module exists for. `st_value` 0x12345 sits in a
    /// segment shifted by 0x10000, so the probe belongs at 0x2345.
    #[test]
    fn a_symbol_address_is_converted_to_a_file_offset() {
        let elf = elf_with_symbol("SSL_write", 0x12345);
        assert_eq!(
            function_file_offset(&elf, "SSL_write"),
            Ok(0x2345),
            "st_value must be shifted by (p_vaddr - p_offset), not used raw"
        );
    }

    /// A real `libssl` exports `SSL_write@@OPENSSL_3.0.0`.
    #[test]
    fn a_versioned_symbol_matches_its_bare_name() {
        let elf = elf_with_symbol("SSL_write@@OPENSSL_3.0.0", 0x12010);
        assert_eq!(function_file_offset(&elf, "SSL_write"), Ok(0x2010));
    }

    #[test]
    fn an_absent_symbol_is_named_rather_than_defaulted() {
        let elf = elf_with_symbol("SSL_read", 0x12345);
        assert_eq!(
            function_file_offset(&elf, "SSL_write"),
            Err(ElfError::NoSuchSymbol("SSL_write".into())),
            "there is no sensible fallback offset; a wrong one probes unrelated code"
        );
    }

    /// An address outside every loadable segment has no file offset at all.
    #[test]
    fn an_unmapped_address_is_refused() {
        let elf = elf_with_symbol("SSL_write", 0x9_0000);
        assert_eq!(
            function_file_offset(&elf, "SSL_write"),
            Err(ElfError::NotMapped("SSL_write".into()))
        );
    }

    #[test]
    fn non_elf_and_wrong_class_are_refused_distinctly() {
        assert_eq!(
            function_file_offset(&[0u8; 0x40], "x"),
            Err(ElfError::NotElf)
        );
        let mut e = elf_with_symbol("SSL_write", 0x12345);
        e[4] = 1; // 32-bit
        assert_eq!(
            function_file_offset(&e, "SSL_write"),
            Err(ElfError::Unsupported)
        );
    }

    /// A data symbol is not a probe site.
    #[test]
    fn a_non_function_symbol_is_not_matched() {
        let mut elf = elf_with_symbol("SSL_write", 0x12345);
        let sym1 = 0x200 + 24;
        elf[sym1 + 4] = 1; // STT_OBJECT
        assert_eq!(
            function_file_offset(&elf, "SSL_write"),
            Err(ElfError::NoSuchSymbol("SSL_write".into()))
        );
    }
}
