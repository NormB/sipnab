// SPDX-License-Identifier: MIT OR Apache-2.0

//! Raw frame addresses and image identity for the crash report.
//!
//! Every published sipnab binary is stripped, so the symbolized backtrace the
//! standard library prints names no functions. What survives stripping is the
//! address of each frame and the identity of the file it came from: the GNU
//! build ID on Linux, the Mach-O UUID on macOS. With those two facts and the
//! symbol file published beside the release (`sipnab-<version>-<target>.debug`
//! or the zipped `.dSYM`), a maintainer resolves the frames with `addr2line`,
//! `llvm-symbolizer` or `atos` on their own machine.
//!
//! The parsing and rendering here are pure functions over bytes and numbers, so
//! the tests drive them with hand-built inputs. The platform glue that feeds
//! them (`dl_iterate_phdr`, the dyld image list, the unwinder) is thin and is
//! exercised by the `--panic-selftest` integration test.

/// One image (the executable or a shared library) mapped into this process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Image {
    /// File the image was loaded from.
    pub path: String,
    /// Amount added to every address in the image's own file to get its
    /// runtime address: the load base of a position-independent ELF, or the
    /// dyld slide of a Mach-O image. `runtime - base` is the address a symbol
    /// file uses.
    pub base: usize,
    /// Runtime address ranges `[start, end)` the image occupies.
    pub ranges: Vec<(usize, usize)>,
    /// GNU build ID or Mach-O UUID bytes, when the image carries one.
    pub id: Option<Vec<u8>>,
}

/// What kind of identity [`Image::id`] holds, named for the report.
pub const ID_LABEL: &str = if cfg!(target_os = "macos") {
    "UUID"
} else {
    "Build ID"
};

/// ELF note type of a GNU build ID (`NT_GNU_BUILD_ID`).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const NT_GNU_BUILD_ID: u32 = 3;

/// Find the GNU build ID in the contents of an ELF note segment.
///
/// # Arguments
/// * `notes` - the bytes of one `PT_NOTE` segment, in the host's byte order.
/// * `align` - the segment's alignment (4 or 8); names and descriptors are
///   padded to it.
///
/// # Returns
/// The descriptor of the first note named `GNU` with type 3, or `None` when
/// there is none or the notes are truncated. Pure.
///
/// Parsed on every platform so the tests run everywhere; only the Linux image
/// walk calls it outside them.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn parse_gnu_build_id(notes: &[u8], align: usize) -> Option<Vec<u8>> {
    let align = align.max(4);
    let pad = |n: usize| n.checked_next_multiple_of(align);
    let word = |at: usize| -> Option<u32> {
        let b = notes.get(at..at.checked_add(4)?)?;
        Some(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
    };
    let mut at = 0usize;
    while at < notes.len() {
        let namesz = word(at)? as usize;
        let descsz = word(at + 4)? as usize;
        let ty = word(at + 8)?;
        let name_at = at.checked_add(12)?;
        let desc_at = name_at.checked_add(pad(namesz)?)?;
        let next = desc_at.checked_add(pad(descsz)?)?;
        let name = notes.get(name_at..name_at.checked_add(namesz)?)?;
        let desc = notes.get(desc_at..desc_at.checked_add(descsz)?)?;
        if ty == NT_GNU_BUILD_ID && name == b"GNU\0" {
            return Some(desc.to_vec());
        }
        at = next;
    }
    None
}

/// Identity and segments read from an in-memory Mach-O image.
///
/// Parsed on every platform so the tests run everywhere; only the macOS image
/// walk calls it outside them.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MachInfo {
    /// The `LC_UUID` payload.
    pub uuid: Option<Vec<u8>>,
    /// `(vmaddr, vmsize)` of every `LC_SEGMENT_64` that maps memory with some
    /// access (`__PAGEZERO`, which has none, is left out).
    pub segments: Vec<(u64, u64)>,
}

/// Parse a 64-bit Mach-O header and its load commands.
///
/// # Arguments
/// * `image` - bytes starting at the `mach_header_64`, at least as long as
///   the header plus `sizeofcmds`.
///
/// # Returns
/// The UUID and mapped segments, or `None` when the magic is not a 64-bit
/// Mach-O or a load command runs past the end. Pure.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn parse_macho(image: &[u8]) -> Option<MachInfo> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_UUID: u32 = 0x1b;
    const HEADER: usize = 32;
    let u32_at = |at: usize| -> Option<u32> {
        let b = image.get(at..at.checked_add(4)?)?;
        Some(u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
    };
    let u64_at = |at: usize| -> Option<u64> {
        let b = image.get(at..at.checked_add(8)?)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(b);
        Some(u64::from_ne_bytes(a))
    };
    if u32_at(0)? != MH_MAGIC_64 {
        return None;
    }
    let ncmds = u32_at(16)?;
    let sizeofcmds = u32_at(20)? as usize;
    let end = HEADER.checked_add(sizeofcmds)?;
    if image.len() < end {
        return None;
    }
    let mut info = MachInfo::default();
    let mut at = HEADER;
    for _ in 0..ncmds {
        let cmd = u32_at(at)?;
        let size = u32_at(at + 4)? as usize;
        if size < 8 || at.checked_add(size)? > end {
            return None;
        }
        match cmd {
            LC_UUID if size >= 24 => {
                info.uuid = Some(image.get(at + 8..at + 24)?.to_vec());
            }
            LC_SEGMENT_64 if size >= 72 => {
                let vmaddr = u64_at(at + 24)?;
                let vmsize = u64_at(at + 32)?;
                let initprot = u32_at(at + 60)?;
                if initprot != 0 && vmsize != 0 {
                    info.segments.push((vmaddr, vmsize));
                }
            }
            _ => {}
        }
        at += size;
    }
    Some(info)
}

/// Which image holds `addr`, and the address a symbol file uses for it.
///
/// # Returns
/// `(index into images, addr - base)` for the first image whose ranges contain
/// `addr`, or `None`. Pure.
pub fn locate(addr: usize, images: &[Image]) -> Option<(usize, usize)> {
    images.iter().enumerate().find_map(|(i, img)| {
        img.ranges
            .iter()
            .any(|&(start, end)| (start..end).contains(&addr))
            .then(|| (i, addr.wrapping_sub(img.base)))
    })
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// The file name part of an image path, for the `image+0x…` frame labels.
fn short_name(path: &str) -> &str {
    path.rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
}

/// Render the report's image section and, when `frames` is given, the raw
/// frame list.
///
/// # Arguments
/// * `images` - loaded images; the first is the executable.
/// * `target` - the Rust target triple the binary was built for, which names
///   the symbol file to download.
/// * `frames` - runtime return addresses, innermost first. `None` when
///   backtrace capture is disabled. Each is labeled with its call site,
///   the return address minus one, relative to its image.
///
/// # Returns
/// The section text, newline-terminated. Pure.
pub fn render(images: &[Image], target: &str, frames: Option<&[usize]>) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("Image:\n");
    match images.first() {
        Some(exe) => {
            let id = exe.id.as_deref().map_or_else(|| "none".to_string(), hex);
            let _ = writeln!(out, "  Path:      {}", exe.path);
            let _ = writeln!(out, "  {ID_LABEL}:  {id}");
            let _ = writeln!(out, "  Load base: {:#x}", exe.base);
        }
        None => out.push_str("  (the loaded images could not be listed on this platform)\n"),
    }
    let _ = writeln!(out, "  Target:    {target}");
    if let Some(frames) = frames {
        out.push_str(
            "\nRaw frames (runtime return address, then image+address of the call in\n\
             that image's file. Resolve these against the symbol file named by\n\
             the ID above):\n",
        );
        for (n, &addr) in frames.iter().enumerate() {
            // Every frame is a return address, one past its call. Locate and
            // label the call itself (`addr - 1`), so a symbolizer names the
            // calling line and not the one after it. The raw column stays the
            // exact value the unwinder returned.
            let call = addr.saturating_sub(1);
            let _ = match locate(call, images) {
                Some((i, rel)) => writeln!(
                    out,
                    "  {n:>3}  {addr:#x}  {}+{rel:#x}",
                    short_name(&images[i].path)
                ),
                None => writeln!(out, "  {n:>3}  {addr:#x}  ?"),
            };
        }
    }
    out
}

/// Upper bound on the frames collected, so a runaway stack cannot make the
/// panic hook allocate without limit.
pub const MAX_FRAMES: usize = 256;

/// The images mapped into this process, executable first.
///
/// Linux walks `dl_iterate_phdr`, which reports the executable first (with an
/// empty name, resolved here through `/proc/self/exe`). Empty on platforms
/// without glue.
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub fn loaded_images() -> Vec<Image> {
    /// Called once per loaded object; `data` is the `Vec<Image>` being built.
    unsafe extern "C" fn each(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        // SAFETY: dl_iterate_phdr passes a valid `info` for the duration of
        // the call, and `data` is the `&mut Vec<Image>` handed in below.
        let (info, images) = unsafe { (&*info, &mut *data.cast::<Vec<Image>>()) };
        let base = info.dlpi_addr as usize;
        let path = if info.dlpi_name.is_null() {
            String::new()
        } else {
            // SAFETY: a non-null dlpi_name is a NUL-terminated C string owned
            // by the dynamic loader for the lifetime of the object.
            unsafe { std::ffi::CStr::from_ptr(info.dlpi_name) }
                .to_string_lossy()
                .into_owned()
        };
        let phdrs: &[libc::Elf64_Phdr] = if info.dlpi_phdr.is_null() {
            &[]
        } else {
            // SAFETY: dlpi_phdr points at dlpi_phnum program headers of the
            // mapped object, valid for the duration of the callback.
            unsafe { std::slice::from_raw_parts(info.dlpi_phdr, usize::from(info.dlpi_phnum)) }
        };
        let mut ranges = Vec::new();
        let mut id = None;
        for ph in phdrs {
            let start = base.wrapping_add(ph.p_vaddr as usize);
            let len = ph.p_memsz as usize;
            match ph.p_type {
                libc::PT_LOAD => ranges.push((start, start.wrapping_add(len))),
                libc::PT_NOTE if id.is_none() && len > 0 => {
                    // SAFETY: a PT_NOTE segment lies inside a PT_LOAD of the
                    // same object, which is mapped readable while it is loaded.
                    let notes = unsafe { std::slice::from_raw_parts(start as *const u8, len) };
                    id = parse_gnu_build_id(notes, ph.p_align as usize);
                }
                _ => {}
            }
        }
        images.push(Image {
            path,
            base,
            ranges,
            id,
        });
        0
    }

    let mut images: Vec<Image> = Vec::new();
    // SAFETY: `each` matches the callback signature, never unwinds, and only
    // touches `images` through the pointer passed here.
    unsafe { libc::dl_iterate_phdr(Some(each), (&raw mut images).cast()) };
    if let Some(exe) = images.first_mut()
        && exe.path.is_empty()
    {
        exe.path = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<executable>".to_string());
    }
    images
}

/// The images mapped into this process, executable first.
///
/// macOS reads dyld's image list: image 0 is the executable. `base` is the
/// dyld slide, so `runtime - base` is the address in the binary and its
/// `.dSYM`, which is what `atos -o` and `llvm-symbolizer` take.
#[cfg(target_os = "macos")]
pub fn loaded_images() -> Vec<Image> {
    unsafe extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_header(index: u32) -> *const u8;
        fn _dyld_get_image_vmaddr_slide(index: u32) -> isize;
        fn _dyld_get_image_name(index: u32) -> *const libc::c_char;
    }
    let mut images = Vec::new();
    // SAFETY: the dyld image-list functions take an index below
    // `_dyld_image_count()` and return pointers dyld owns for as long as the
    // image stays loaded; nothing here unloads images.
    unsafe {
        for i in 0.._dyld_image_count() {
            let header = _dyld_get_image_header(i);
            if header.is_null() {
                continue;
            }
            // mach_header_64: sizeofcmds is the u32 at offset 20.
            let sizeofcmds = std::ptr::read_unaligned(header.add(20).cast::<u32>()) as usize;
            let bytes = std::slice::from_raw_parts(header, 32 + sizeofcmds);
            let Some(info) = parse_macho(bytes) else {
                continue;
            };
            let slide = _dyld_get_image_vmaddr_slide(i) as usize;
            let name = _dyld_get_image_name(i);
            let path = if name.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(name)
                    .to_string_lossy()
                    .into_owned()
            };
            let ranges = info
                .segments
                .iter()
                .map(|&(addr, size)| {
                    let start = (addr as usize).wrapping_add(slide);
                    (start, start.wrapping_add(size as usize))
                })
                .collect();
            images.push(Image {
                path,
                base: slide,
                ranges,
                id: info.uuid,
            });
        }
    }
    images
}

/// No image list on this platform (32-bit Linux included: the program
/// header walk above reads 64-bit headers, and no 32-bit target is built).
#[cfg(not(any(
    all(target_os = "linux", target_pointer_width = "64"),
    target_os = "macos"
)))]
pub fn loaded_images() -> Vec<Image> {
    Vec::new()
}

/// Return addresses of the calling thread's stack, innermost first, at most
/// [`MAX_FRAMES`] of them.
///
/// Walks the stack with the platform unwinder (`_Unwind_Backtrace`), the same
/// one the standard library's backtrace uses, so it needs no symbols and
/// works on a stripped binary.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn frame_addresses() -> Vec<usize> {
    /// Opaque unwinder context.
    #[repr(C)]
    struct UnwindContext {
        _private: [u8; 0],
    }
    /// `_URC_NO_REASON`: keep walking.
    const CONTINUE: libc::c_int = 0;
    /// `_URC_END_OF_STACK`: stop.
    const STOP: libc::c_int = 5;
    unsafe extern "C" {
        fn _Unwind_Backtrace(
            trace: extern "C" fn(*mut UnwindContext, *mut libc::c_void) -> libc::c_int,
            arg: *mut libc::c_void,
        ) -> libc::c_int;
        fn _Unwind_GetIP(ctx: *mut UnwindContext) -> usize;
    }
    /// Record one frame. Never allocates: the vector is pre-sized.
    extern "C" fn each(ctx: *mut UnwindContext, arg: *mut libc::c_void) -> libc::c_int {
        // SAFETY: `arg` is the `&mut Vec<usize>` passed below, and `ctx` is
        // the live context the unwinder hands its callback.
        let (frames, ip) = unsafe { (&mut *arg.cast::<Vec<usize>>(), _Unwind_GetIP(ctx)) };
        if ip != 0 {
            frames.push(ip);
        }
        if frames.len() >= MAX_FRAMES {
            STOP
        } else {
            CONTINUE
        }
    }
    let mut frames: Vec<usize> = Vec::with_capacity(MAX_FRAMES);
    // SAFETY: `each` has the callback ABI the unwinder expects, does not
    // unwind, and stops before the pre-sized vector would reallocate.
    unsafe { _Unwind_Backtrace(each, (&raw mut frames).cast()) };
    frames
}

/// No unwinder glue on this platform.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn frame_addresses() -> Vec<usize> {
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build one ELF note in host byte order, padded to `align`.
    fn note(name: &[u8], ty: u32, desc: &[u8], align: usize) -> Vec<u8> {
        let pad = |n: usize| n.div_ceil(align) * align;
        let mut v = Vec::new();
        v.extend_from_slice(&(name.len() as u32).to_ne_bytes());
        v.extend_from_slice(&(desc.len() as u32).to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        let mut n = name.to_vec();
        n.resize(pad(name.len()), 0);
        v.extend_from_slice(&n);
        let mut d = desc.to_vec();
        d.resize(pad(desc.len()), 0);
        v.extend_from_slice(&d);
        v
    }

    const ID: [u8; 20] = [
        0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ];

    /// The build ID is found after an unrelated GNU note, at 4-byte alignment.
    #[test]
    fn build_id_is_found_after_another_note() {
        let mut seg = note(b"GNU\0", 1, &[0, 0, 0, 0, 3, 2, 0, 0], 4);
        seg.extend(note(b"GNU\0", NT_GNU_BUILD_ID, &ID, 4));
        assert_eq!(parse_gnu_build_id(&seg, 4), Some(ID.to_vec()));
    }

    /// An 8-aligned note segment pads the name and descriptor to 8.
    #[test]
    fn build_id_is_found_in_an_eight_aligned_segment() {
        let mut seg = note(b"GNU\0", 5, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12], 8);
        seg.extend(note(b"GNU\0", NT_GNU_BUILD_ID, &ID, 8));
        assert_eq!(parse_gnu_build_id(&seg, 8), Some(ID.to_vec()));
    }

    /// A type-3 note under another owner's name is not a GNU build ID.
    #[test]
    fn a_type_three_note_from_another_owner_is_ignored() {
        let seg = note(b"Go\0\0", NT_GNU_BUILD_ID, &ID, 4);
        assert_eq!(parse_gnu_build_id(&seg, 4), None);
    }

    /// A descriptor that runs past the segment is refused, not read past.
    #[test]
    fn a_truncated_note_is_refused() {
        let seg = note(b"GNU\0", NT_GNU_BUILD_ID, &ID, 4);
        assert_eq!(parse_gnu_build_id(&seg[..seg.len() - 4], 4), None);
        assert_eq!(parse_gnu_build_id(&[], 4), None);
    }

    /// A 64-bit Mach-O header with `__PAGEZERO`, `__TEXT` and `LC_UUID`.
    fn macho() -> Vec<u8> {
        let seg = |name: &[u8], vmaddr: u64, vmsize: u64, prot: u32| {
            let mut c = Vec::new();
            c.extend_from_slice(&0x19u32.to_ne_bytes()); // LC_SEGMENT_64
            c.extend_from_slice(&72u32.to_ne_bytes());
            let mut n = name.to_vec();
            n.resize(16, 0);
            c.extend_from_slice(&n);
            c.extend_from_slice(&vmaddr.to_ne_bytes());
            c.extend_from_slice(&vmsize.to_ne_bytes());
            c.extend_from_slice(&0u64.to_ne_bytes()); // fileoff
            c.extend_from_slice(&vmsize.to_ne_bytes()); // filesize
            c.extend_from_slice(&prot.to_ne_bytes()); // maxprot
            c.extend_from_slice(&prot.to_ne_bytes()); // initprot
            c.extend_from_slice(&0u32.to_ne_bytes()); // nsects
            c.extend_from_slice(&0u32.to_ne_bytes()); // flags
            c
        };
        let mut cmds = Vec::new();
        cmds.extend(seg(b"__PAGEZERO", 0, 0x1_0000_0000, 0));
        cmds.extend(seg(b"__TEXT", 0x1_0000_0000, 0x4000, 5));
        cmds.extend_from_slice(&0x1bu32.to_ne_bytes()); // LC_UUID
        cmds.extend_from_slice(&24u32.to_ne_bytes());
        cmds.extend_from_slice(&ID[..16]);
        let mut h = Vec::new();
        h.extend_from_slice(&0xfeed_facfu32.to_ne_bytes());
        h.extend_from_slice(&0x0100_000cu32.to_ne_bytes()); // cputype arm64
        h.extend_from_slice(&0u32.to_ne_bytes()); // cpusubtype
        h.extend_from_slice(&2u32.to_ne_bytes()); // MH_EXECUTE
        h.extend_from_slice(&3u32.to_ne_bytes()); // ncmds
        h.extend_from_slice(&(cmds.len() as u32).to_ne_bytes());
        h.extend_from_slice(&0u32.to_ne_bytes()); // flags
        h.extend_from_slice(&0u32.to_ne_bytes()); // reserved
        h.extend(cmds);
        h
    }

    /// The UUID and the mapped `__TEXT` segment are read; `__PAGEZERO`,
    /// which maps nothing accessible, is left out.
    #[test]
    fn macho_uuid_and_segments_are_read() {
        let info = parse_macho(&macho()).expect("valid Mach-O");
        assert_eq!(info.uuid, Some(ID[..16].to_vec()));
        assert_eq!(info.segments, vec![(0x1_0000_0000, 0x4000)]);
    }

    /// A 32-bit or foreign magic, or a load command running off the end, is
    /// refused.
    #[test]
    fn a_malformed_macho_is_refused() {
        let mut bad = macho();
        bad[0] ^= 0xff;
        assert_eq!(parse_macho(&bad), None);
        let good = macho();
        assert_eq!(parse_macho(&good[..good.len() - 8]), None);
        assert_eq!(parse_macho(&good[..10]), None);
    }

    /// Two images: a PIE executable at 0x5555_0000_0000 and libc.
    fn images() -> Vec<Image> {
        vec![
            Image {
                path: "/usr/bin/sipnab".into(),
                base: 0x5555_0000_0000,
                ranges: vec![(0x5555_0000_0000, 0x5555_0010_0000)],
                id: Some(ID.to_vec()),
            },
            Image {
                path: "/lib/x86_64-linux-gnu/libc.so.6".into(),
                base: 0x7f00_0000_0000,
                ranges: vec![(0x7f00_0002_0000, 0x7f00_0003_0000)],
                id: None,
            },
        ]
    }

    /// An address resolves to its image and to `address - base`; the end of
    /// a range is exclusive; an unmapped address resolves to nothing.
    #[test]
    fn locate_maps_an_address_to_its_image_and_file_address() {
        let imgs = images();
        assert_eq!(locate(0x5555_0000_1234, &imgs), Some((0, 0x1234)));
        assert_eq!(locate(0x7f00_0002_0010, &imgs), Some((1, 0x2_0010)));
        assert_eq!(locate(0x5555_0010_0000, &imgs), None);
        assert_eq!(locate(0x10, &imgs), None);
    }

    /// Hex is lowercase and zero-padded per byte.
    #[test]
    fn hex_is_lowercase_and_padded() {
        assert_eq!(hex(&[0x0a, 0xff, 0x00]), "0aff00");
    }

    /// (c) The report records the executable's identity, load base and
    /// target, and every frame as a raw address plus image-relative address.
    #[test]
    fn the_render_records_identity_load_base_and_raw_frames() {
        let out = render(
            &images(),
            "x86_64-unknown-linux-gnu",
            Some(&[0x5555_0000_1234, 0x7f00_0002_0010, 0x42]),
        );
        assert!(out.contains("/usr/bin/sipnab"), "{out}");
        assert!(
            out.contains(&format!(
                "{ID_LABEL}:  deadbeef0102030405060708090a0b0c0d0e0f10"
            )),
            "{out}"
        );
        assert!(out.contains("Load base: 0x555500000000"), "{out}");
        assert!(out.contains("Target:    x86_64-unknown-linux-gnu"), "{out}");
        // The unwinder yields RETURN addresses, one past the call. The
        // image-relative column names the call instruction instead (minus
        // one), which is where a symbolizer reports the calling line rather
        // than whatever follows it. Measured on a release build: the
        // return address resolved `sipnab::main` to line 175, the call site
        // to 152, the panic's real line.
        assert!(out.contains("0x555500001234  sipnab+0x1233"), "{out}");
        assert!(out.contains("0x7f0000020010  libc.so.6+0x2000f"), "{out}");
        assert!(out.contains("0x42  ?"), "{out}");
    }

    /// With backtrace capture disabled the identity is still recorded, and
    /// no frame list is.
    #[test]
    fn the_render_without_frames_still_names_the_image() {
        let out = render(&images(), "x86_64-unknown-linux-gnu", None);
        assert!(out.contains("deadbeef"), "{out}");
        assert!(!out.contains("sipnab+0x"), "{out}");
    }

    /// An image without an identity says so rather than printing nothing.
    #[test]
    fn a_missing_identity_is_named() {
        let mut imgs = images();
        imgs[0].id = None;
        let out = render(&imgs, "t", None);
        assert!(out.contains(&format!("{ID_LABEL}:  none")), "{out}");
    }

    /// Live, on the platforms with glue: this test binary is the first image,
    /// it carries an identity, and its range holds the address of one of its
    /// own functions.
    #[test]
    #[cfg(any(
        all(target_os = "linux", target_pointer_width = "64"),
        target_os = "macos"
    ))]
    fn the_running_executable_is_the_first_image_and_carries_an_identity() {
        let imgs = loaded_images();
        assert!(!imgs.is_empty(), "no images enumerated");
        let here =
            the_running_executable_is_the_first_image_and_carries_an_identity as fn() as usize;
        let (idx, _) = locate(here, &imgs).expect("this function lies in a loaded image");
        assert_eq!(idx, 0, "the executable must be the first image: {imgs:?}");
        let id = imgs[0]
            .id
            .as_ref()
            .expect("the executable carries an identity");
        assert!(id.len() >= 16, "implausible identity {id:?}");
    }

    /// Live: the unwinder yields several frames, and the innermost ones lie in
    /// this executable.
    #[test]
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn the_unwinder_yields_frames_in_this_executable() {
        let frames = frame_addresses();
        assert!(frames.len() >= 3, "only {} frames", frames.len());
        assert!(frames.len() <= MAX_FRAMES);
        let imgs = loaded_images();
        let in_exe = frames
            .iter()
            .filter(|&&f| matches!(locate(f, &imgs), Some((0, _))))
            .count();
        assert!(
            in_exe >= 2,
            "only {in_exe} frames in the executable: {frames:x?}"
        );
    }
}
