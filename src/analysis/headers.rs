//! Format-specific header parsing for magic hits: ELF, PE, Android boot
//! image v0-v4, DEX. Parsers are offset-relative so embedded images inside
//! firmware blobs decode too. Output is display lines for the info pane.

fn rd<const N: usize>(data: &[u8], off: usize) -> Option<[u8; N]> {
    data.get(off..off + N)?.try_into().ok()
}

fn u16e(data: &[u8], off: usize, le: bool) -> Option<u16> {
    rd::<2>(data, off).map(|b| {
        if le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }
    })
}

fn u32e(data: &[u8], off: usize, le: bool) -> Option<u32> {
    rd::<4>(data, off).map(|b| {
        if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }
    })
}

fn u64e(data: &[u8], off: usize, le: bool) -> Option<u64> {
    rd::<8>(data, off).map(|b| {
        if le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        }
    })
}

fn cstr(data: &[u8], off: usize, max: usize) -> String {
    data.get(off..)
        .unwrap_or(&[])
        .iter()
        .take(max)
        .take_while(|&&b| b != 0)
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

pub fn machine_name(m: u16) -> &'static str {
    match m {
        0x02 => "SPARC",
        0x03 => "x86",
        0x08 => "MIPS",
        0x14 => "PowerPC",
        0x15 => "PowerPC64",
        0x16 => "S390",
        0x28 => "ARM",
        0x2A => "SuperH",
        0x32 => "IA-64",
        0x3E => "x86-64",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        0xF7 => "BPF",
        0x102 => "LoongArch",
        _ => "unknown",
    }
}

/// ELF header at `off` (offset of `\x7fELF`).
pub fn parse_elf(data: &[u8], off: usize) -> Vec<String> {
    let mut out = Vec::new();
    let Some(ident) = data.get(off..off + 16) else {
        return vec!["ELF: truncated ident".into()];
    };
    let is64 = ident[4] == 2;
    let le = ident[5] == 1;
    out.push(format!(
        "ELF{} {}",
        if is64 { "64" } else { "32" },
        if le { "little-endian" } else { "big-endian" }
    ));
    if let Some(m) = u16e(data, off + 0x12, le) {
        out.push(format!("machine: {} (0x{m:X})", machine_name(m)));
    }
    let (entry, phoff, shnum_off) = if is64 {
        (
            u64e(data, off + 0x18, le),
            u64e(data, off + 0x20, le),
            off + 0x3C,
        )
    } else {
        (
            u32e(data, off + 0x18, le).map(u64::from),
            u32e(data, off + 0x1C, le).map(u64::from),
            off + 0x30,
        )
    };
    if let Some(e) = entry {
        out.push(format!("entry: 0x{e:X}"));
    }
    if let Some(p) = phoff {
        out.push(format!("phoff: 0x{p:X}"));
    }
    if let Some(n) = u16e(data, shnum_off, le) {
        out.push(format!("sections: {n}"));
    }
    out
}

/// PE image starting at the MZ header at `off`.
pub fn parse_pe(data: &[u8], off: usize) -> Vec<String> {
    let mut out = Vec::new();
    let Some(e_lfanew) = u32e(data, off + 0x3C, true) else {
        return vec!["MZ: truncated header".into()];
    };
    let pe = off + e_lfanew as usize;
    if rd::<4>(data, pe) != Some(*b"PE\0\0") {
        return vec!["MZ: DOS executable (no PE header)".into()];
    }
    let machine = u16e(data, pe + 4, true).unwrap_or(0);
    let mname = match machine {
        0x014C => "x86",
        0x8664 => "x86-64",
        0x01C0 | 0x01C2 | 0x01C4 => "ARM",
        0xAA64 => "ARM64",
        0x0200 => "IA-64",
        0x5032 => "RISC-V 32",
        0x5064 => "RISC-V 64",
        _ => "unknown",
    };
    out.push(format!("PE machine: {mname} (0x{machine:X})"));
    let nsections = u16e(data, pe + 6, true).unwrap_or(0);
    let opt_size = u16e(data, pe + 20, true).unwrap_or(0) as usize;
    let opt = pe + 24;
    if let Some(magic) = u16e(data, opt, true) {
        let kind = match magic {
            0x10B => "PE32",
            0x20B => "PE32+",
            _ => "unknown optional header",
        };
        out.push(format!("format: {kind}"));
    }
    if let Some(ep) = u32e(data, opt + 16, true) {
        out.push(format!("entrypoint RVA: 0x{ep:X}"));
    }
    out.push(format!("sections: {nsections}"));
    let sect_table = opt + opt_size;
    for i in 0..(nsections as usize).min(16) {
        let s = sect_table + i * 40;
        let name = cstr(data, s, 8);
        let vsize = u32e(data, s + 8, true).unwrap_or(0);
        let vaddr = u32e(data, s + 12, true).unwrap_or(0);
        let rsize = u32e(data, s + 16, true).unwrap_or(0);
        out.push(format!(
            "  {:<8} vaddr 0x{vaddr:08X} vsize 0x{vsize:X} raw 0x{rsize:X}",
            name
        ));
    }
    out
}

fn decode_os_version(v: u32) -> String {
    if v == 0 {
        return "0".into();
    }
    let a = (v >> 25) & 0x7F;
    let b = (v >> 18) & 0x7F;
    let c = (v >> 11) & 0x7F;
    let year = ((v >> 4) & 0x7F) + 2000;
    let month = v & 0xF;
    format!("{a}.{b}.{c} (patch {year}-{month:02})")
}

/// Android boot image at `off` (offset of `ANDROID!`). Handles v0-v4: the
/// header_version field lives at +40 in every layout, which is how AOSP
/// itself discriminates.
pub fn parse_bootimg(data: &[u8], off: usize) -> Vec<String> {
    let mut out = Vec::new();
    let Some(version) = u32e(data, off + 40, true) else {
        return vec!["bootimg: truncated".into()];
    };
    let v = if version <= 4 { version } else { 0 };
    out.push(format!("Android boot image v{v}"));
    if v >= 3 {
        // v3/v4 layout
        let kernel_size = u32e(data, off + 8, true).unwrap_or(0);
        let ramdisk_size = u32e(data, off + 12, true).unwrap_or(0);
        let os_version = u32e(data, off + 16, true).unwrap_or(0);
        let header_size = u32e(data, off + 20, true).unwrap_or(0);
        out.push(format!("kernel_size: 0x{kernel_size:X}"));
        out.push(format!("ramdisk_size: 0x{ramdisk_size:X}"));
        out.push(format!("os_version: {}", decode_os_version(os_version)));
        out.push(format!("header_size: {header_size}"));
        out.push(format!("cmdline: {}", cstr(data, off + 44, 1536 + 512)));
        if v == 4
            && let Some(sig) = u32e(data, off + 44 + 1536 + 512, true)
        {
            out.push(format!("signature_size: 0x{sig:X}"));
        }
    } else {
        let f = |o: usize| u32e(data, off + o, true).unwrap_or(0);
        out.push(format!("kernel_size: 0x{:X} @ 0x{:X}", f(8), f(12)));
        out.push(format!("ramdisk_size: 0x{:X} @ 0x{:X}", f(16), f(20)));
        out.push(format!("second_size: 0x{:X} @ 0x{:X}", f(24), f(28)));
        out.push(format!("tags_addr: 0x{:X}", f(32)));
        out.push(format!("page_size: {}", f(36)));
        out.push(format!("os_version: {}", decode_os_version(f(44))));
        out.push(format!("name: {}", cstr(data, off + 48, 16)));
        out.push(format!("cmdline: {}", cstr(data, off + 64, 512)));
        if v >= 1 {
            let dtbo_size = f(1632);
            let dtbo_off = u64e(data, off + 1636, true).unwrap_or(0);
            let header_size = f(1644);
            out.push(format!("recovery_dtbo: 0x{dtbo_size:X} @ 0x{dtbo_off:X}"));
            out.push(format!("header_size: {header_size}"));
        }
        if v == 2 {
            let dtb_size = f(1648);
            let dtb_addr = u64e(data, off + 1652, true).unwrap_or(0);
            out.push(format!("dtb: 0x{dtb_size:X} @ 0x{dtb_addr:X}"));
        }
    }
    out
}

/// DEX header at `off` (offset of `dex\n`).
pub fn parse_dex(data: &[u8], off: usize) -> Vec<String> {
    let mut out = Vec::new();
    let version = cstr(data, off + 4, 3);
    out.push(format!("DEX version {version}"));
    if let Some(ck) = u32e(data, off + 8, true) {
        out.push(format!("checksum (adler32): 0x{ck:08X}"));
    }
    if let Some(fs) = u32e(data, off + 32, true) {
        out.push(format!("file_size: 0x{fs:X}"));
    }
    if let Some(n) = u32e(data, off + 96, true) {
        out.push(format!("class_defs: {n}"));
    }
    if let Some(o) = u32e(data, off + 100, true) {
        out.push(format!("class_defs_off: 0x{o:X}"));
    }
    out
}

/// Dispatch on a magic hit name; None when there's no detail parser.
pub fn parse_for(name: &str, data: &[u8], off: usize) -> Option<Vec<String>> {
    match name {
        "ELF" => Some(parse_elf(data, off)),
        "MZ/DOS executable" => Some(parse_pe(data, off)),
        "Android boot image" => Some(parse_bootimg(data, off)),
        n if n.starts_with("DEX") => Some(parse_dex(data, off)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf64_fields() {
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = 2; // 64-bit
        h[5] = 1; // LE
        h[0x12] = 0x3E; // x86-64
        h[0x18..0x20].copy_from_slice(&0x401000u64.to_le_bytes());
        h[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
        h[0x3C..0x3E].copy_from_slice(&29u16.to_le_bytes());
        let lines = parse_elf(&h, 0);
        assert!(lines[0].contains("ELF64 little-endian"));
        assert!(lines.iter().any(|l| l.contains("x86-64")));
        assert!(lines.iter().any(|l| l.contains("entry: 0x401000")));
        assert!(lines.iter().any(|l| l.contains("sections: 29")));
    }

    #[test]
    fn bootimg_v2() {
        let mut h = vec![0u8; 1660];
        h[..8].copy_from_slice(b"ANDROID!");
        h[8..12].copy_from_slice(&0x800000u32.to_le_bytes()); // kernel_size
        h[36..40].copy_from_slice(&2048u32.to_le_bytes()); // page_size
        h[40..44].copy_from_slice(&2u32.to_le_bytes()); // header_version
        h[64..68].copy_from_slice(b"con=");
        let lines = parse_bootimg(&h, 0);
        assert!(lines[0].contains("v2"));
        assert!(lines.iter().any(|l| l.contains("kernel_size: 0x800000")));
        assert!(lines.iter().any(|l| l.contains("page_size: 2048")));
        assert!(lines.iter().any(|l| l.contains("cmdline: con=")));
        assert!(lines.iter().any(|l| l.starts_with("dtb:")));
    }

    #[test]
    fn bootimg_v3() {
        let mut h = vec![0u8; 4096];
        h[..8].copy_from_slice(b"ANDROID!");
        h[8..12].copy_from_slice(&0x123456u32.to_le_bytes());
        h[40..44].copy_from_slice(&3u32.to_le_bytes());
        h[44..49].copy_from_slice(b"quiet");
        let lines = parse_bootimg(&h, 0);
        assert!(lines[0].contains("v3"));
        assert!(lines.iter().any(|l| l.contains("kernel_size: 0x123456")));
        assert!(lines.iter().any(|l| l.contains("cmdline: quiet")));
    }

    #[test]
    fn dex_header() {
        let mut h = vec![0u8; 112];
        h[..8].copy_from_slice(b"dex\n035\0");
        h[8..12].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        h[96..100].copy_from_slice(&42u32.to_le_bytes());
        let lines = parse_dex(&h, 0);
        assert!(lines[0].contains("035"));
        assert!(lines.iter().any(|l| l.contains("0xDEADBEEF")));
        assert!(lines.iter().any(|l| l.contains("class_defs: 42")));
    }
}
