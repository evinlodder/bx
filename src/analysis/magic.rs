//! Magic byte scanning: whole-file sweep against a signature table.
//!
//! Short/noisy magics carry validators that sanity-check surrounding bytes so
//! firmware blobs don't drown in false positives. Heuristic-only formats are
//! labeled as such in their name.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    Anywhere,
    /// Only match at this absolute file offset.
    FileOffset(u64),
}

type Validator = fn(&[u8], usize) -> bool;

pub struct MagicEntry {
    pub name: &'static str,
    pub category: &'static str,
    pattern: &'static [u8],
    anchor: Anchor,
    validator: Option<Validator>,
}

#[derive(Debug, Clone)]
pub struct MagicHit {
    pub offset: u64,
    pub name: &'static str,
    pub category: &'static str,
}

const fn e(
    name: &'static str,
    category: &'static str,
    pattern: &'static [u8],
    anchor: Anchor,
    validator: Option<Validator>,
) -> MagicEntry {
    MagicEntry {
        name,
        category,
        pattern,
        anchor,
        validator,
    }
}

// --- validators -------------------------------------------------------------

fn at(data: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    data.get(off..off + len)
}

fn u16le(data: &[u8], off: usize) -> Option<u16> {
    at(data, off, 2).map(|b| u16::from_le_bytes(b.try_into().unwrap()))
}

fn u32le(data: &[u8], off: usize) -> Option<u32> {
    at(data, off, 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()))
}

fn v_elf(data: &[u8], off: usize) -> bool {
    // EI_CLASS in {1,2}, EI_DATA in {1,2}, EI_VERSION == 1
    matches!(at(data, off + 4, 3), Some(&[c, d, 1]) if (1..=2).contains(&c) && (1..=2).contains(&d))
}

fn v_mz(data: &[u8], off: usize) -> bool {
    // Require a full DOS header; that alone keeps random "MZ" pairs out.
    at(data, off, 0x40).is_some()
}

fn v_pe(data: &[u8], off: usize) -> bool {
    // Known IMAGE_FILE_MACHINE values
    matches!(
        u16le(data, off + 4),
        Some(
            0x014C
                | 0x0200
                | 0x8664
                | 0x01C0
                | 0x01C2
                | 0x01C4
                | 0xAA64
                | 0x0266
                | 0x0366
                | 0x5032
                | 0x5064
                | 0x01F0
                | 0x01F1
        )
    )
}

fn v_coff_i386(data: &[u8], off: usize) -> bool {
    // section count plausible, optional-header size sane
    matches!(u16le(data, off + 2), Some(1..=96)) && matches!(u16le(data, off + 16), Some(0..=1024))
}

fn v_fat_macho(data: &[u8], off: usize) -> bool {
    // CAFEBABE doubles as the Java class magic; fat Mach-O has < ~30 archs
    // (BE u32 at +4), Java has major version >= 45 there (BE u16 at +6).
    matches!(at(data, off + 4, 4), Some(&[0, 0, 0, n]) if (1..=30).contains(&n))
}

fn v_dex(data: &[u8], off: usize) -> bool {
    matches!(at(data, off + 4, 4), Some(&[b'0', b'3', b'5'..=b'9', 0]))
}

fn v_odex(data: &[u8], off: usize) -> bool {
    matches!(at(data, off + 4, 4), Some(&[b'0', b'3', b'5' | b'6', 0]))
}

fn v_version_digits(data: &[u8], off: usize) -> bool {
    // "vdex"/"oat\n"/"art\n" are followed by an ASCII version like "010\0"
    matches!(at(data, off + 4, 3), Some(v) if v.iter().all(u8::is_ascii_digit))
}

fn v_jffs2(data: &[u8], off: usize) -> bool {
    // little-endian node: magic 0x1985, then a known nodetype
    matches!(
        u16le(data, off + 2),
        Some(0xE001 | 0xE002 | 0x2003 | 0x2004 | 0xE008 | 0x2006)
    )
}

fn v_ext(data: &[u8], off: usize) -> bool {
    // hit is at superblock+0x38; look back to validate superblock fields
    let Some(sb) = off.checked_sub(0x38) else {
        return false;
    };
    let inodes = u32le(data, sb).unwrap_or(0);
    let blocks = u32le(data, sb + 4).unwrap_or(0);
    let first_data_block = u32le(data, sb + 0x14).unwrap_or(99);
    let log_block_size = u32le(data, sb + 0x18).unwrap_or(99);
    inodes > 0 && blocks > 0 && first_data_block <= 1 && log_block_size <= 6
}

fn v_gzip(data: &[u8], off: usize) -> bool {
    // FLG reserved bits must be zero
    matches!(at(data, off + 3, 1), Some(&[f]) if f & 0xE0 == 0)
}

fn v_lzma(data: &[u8], off: usize) -> bool {
    // dict size: power of two between 4 KiB and 256 MiB
    match u32le(data, off + 1) {
        Some(d) => d.is_power_of_two() && (0x1000..=0x1000_0000).contains(&d),
        None => false,
    }
}

fn v_bzip2(data: &[u8], off: usize) -> bool {
    // level digit + pi block magic
    matches!(at(data, off + 3, 1), Some(&[b'1'..=b'9']))
        && at(data, off + 4, 6) == Some(&[0x31, 0x41, 0x59, 0x26, 0x53, 0x59])
}

fn v_tar(data: &[u8], off: usize) -> bool {
    // "ustar" sits at header offset 257; checksum field (offset 148, 8 bytes)
    // must be octal digits / space / NUL
    let Some(hdr) = off.checked_sub(257) else {
        return false;
    };
    matches!(at(data, hdr + 148, 8), Some(ck) if ck
        .iter()
        .all(|&c| c.is_ascii_digit() && c < b'8' || c == b' ' || c == 0))
}

fn v_der_cert(data: &[u8], off: usize) -> bool {
    // SEQUENCE(long form) containing another long-form SEQUENCE = x509 shape
    at(data, off + 4, 2) == Some(&[0x30, 0x82])
}

fn v_pkcs8(data: &[u8], off: usize) -> bool {
    // SEQUENCE { INTEGER(0) version, ... }
    at(data, off + 4, 4) == Some(&[0x02, 0x01, 0x00, 0x30])
}

fn v_pkcs12(data: &[u8], off: usize) -> bool {
    // SEQUENCE { INTEGER(3) version, ... }
    at(data, off + 4, 3) == Some(&[0x02, 0x01, 0x03])
}

fn v_ota_payload(data: &[u8], off: usize) -> bool {
    // u64be file_format_version is 1 or 2
    matches!(at(data, off + 4, 8), Some(&[0, 0, 0, 0, 0, 0, 0, 1 | 2]))
}

fn v_bmp(data: &[u8], off: usize) -> bool {
    // reserved words zero, declared size at least header-sized
    at(data, off + 6, 4) == Some(&[0, 0, 0, 0]) && u32le(data, off + 2).unwrap_or(0) >= 26
}

fn v_protobuf(data: &[u8], off: usize) -> bool {
    // field 1, length-delimited, with a length that fits the file
    matches!(at(data, off + 1, 1), Some(&[l]) if l > 0 && l < 0x80 && (off + 2 + l as usize) <= data.len())
}

fn v_msgpack(data: &[u8], _off: usize) -> bool {
    // fixmap/fixarray with non-trivial content following
    data.len() > 2
}

// --- signature table ---------------------------------------------------------

const EXE: &str = "executable";
const FW: &str = "firmware";
const ARC: &str = "archive";
const CRYPT: &str = "crypto";
const MEDIA: &str = "media";

#[rustfmt::skip]
pub static MAGIC_TABLE: &[MagicEntry] = &[
    // Executables & objects
    e("ELF", EXE, b"\x7fELF", Anchor::Anywhere, Some(v_elf)),
    e("MZ/DOS executable", EXE, b"MZ", Anchor::FileOffset(0), Some(v_mz)),
    e("PE header", EXE, b"PE\0\0", Anchor::Anywhere, Some(v_pe)),
    e("Mach-O 32-bit BE", EXE, &[0xFE, 0xED, 0xFA, 0xCE], Anchor::Anywhere, None),
    e("Mach-O 32-bit LE", EXE, &[0xCE, 0xFA, 0xED, 0xFE], Anchor::Anywhere, None),
    e("Mach-O 64-bit BE", EXE, &[0xFE, 0xED, 0xFA, 0xCF], Anchor::Anywhere, None),
    e("Mach-O 64-bit LE", EXE, &[0xCF, 0xFA, 0xED, 0xFE], Anchor::Anywhere, None),
    e("Mach-O fat binary", EXE, &[0xCA, 0xFE, 0xBA, 0xBE], Anchor::Anywhere, Some(v_fat_macho)),
    e("COFF object (i386)", EXE, &[0x4C, 0x01], Anchor::FileOffset(0), Some(v_coff_i386)),
    e("ar archive / static lib", EXE, b"!<arch>\n", Anchor::Anywhere, None),
    e("DEX (Dalvik executable)", EXE, b"dex\n", Anchor::Anywhere, Some(v_dex)),
    e("ODEX (optimized DEX)", EXE, b"dey\n", Anchor::Anywhere, Some(v_odex)),
    e("VDEX", EXE, b"vdex", Anchor::Anywhere, Some(v_version_digits)),
    e("OAT (Android AOT)", EXE, b"oat\n", Anchor::Anywhere, Some(v_version_digits)),
    e("ART image", EXE, b"art\n", Anchor::Anywhere, Some(v_version_digits)),
    // Firmware & bootloaders
    e("Android boot image", FW, b"ANDROID!", Anchor::Anywhere, None),
    e("Android vendor boot image", FW, b"VNDRBOOT", Anchor::Anywhere, None),
    e("U-Boot uImage", FW, &[0x27, 0x05, 0x19, 0x56], Anchor::Anywhere, None),
    e("Device tree / U-Boot FIT", FW, &[0xD0, 0x0D, 0xFE, 0xED], Anchor::Anywhere, None),
    e("SquashFS (LE)", FW, b"hsqs", Anchor::Anywhere, None),
    e("SquashFS (BE)", FW, b"sqsh", Anchor::Anywhere, None),
    e("SquashFS 3.x (LE)", FW, b"shsq", Anchor::Anywhere, None),
    e("SquashFS 3.x (BE)", FW, b"qshs", Anchor::Anywhere, None),
    e("JFFS2 node (LE)", FW, &[0x85, 0x19], Anchor::Anywhere, Some(v_jffs2)),
    e("UBI erase block", FW, b"UBI#", Anchor::Anywhere, None),
    e("UBIFS superblock", FW, &[0x31, 0x18, 0x10, 0x06], Anchor::Anywhere, None),
    e("YAFFS2 (heuristic)", FW, &[0x03, 0, 0, 0, 0x01, 0, 0, 0, 0xFF, 0xFF], Anchor::Anywhere, None),
    e("cramfs (LE)", FW, &[0x45, 0x3D, 0xCD, 0x28], Anchor::Anywhere, None),
    e("cramfs (BE)", FW, &[0x28, 0xCD, 0x3D, 0x45], Anchor::Anywhere, None),
    e("romfs", FW, b"-rom1fs-", Anchor::Anywhere, None),
    e("ext2/3/4 superblock", FW, &[0x53, 0xEF], Anchor::Anywhere, Some(v_ext)),
    e("F2FS superblock", FW, &[0x10, 0x20, 0xF5, 0xF2], Anchor::Anywhere, None),
    // Archives & compression
    e("gzip", ARC, &[0x1F, 0x8B, 0x08], Anchor::Anywhere, Some(v_gzip)),
    e("zlib (no/low compression)", ARC, &[0x78, 0x01], Anchor::Anywhere, None),
    e("zlib (fast)", ARC, &[0x78, 0x5E], Anchor::Anywhere, None),
    e("zlib (default)", ARC, &[0x78, 0x9C], Anchor::Anywhere, None),
    e("zlib (best)", ARC, &[0x78, 0xDA], Anchor::Anywhere, None),
    e("LZMA", ARC, &[0x5D, 0x00, 0x00], Anchor::Anywhere, Some(v_lzma)),
    e("LZ4 frame", ARC, &[0x04, 0x22, 0x4D, 0x18], Anchor::Anywhere, None),
    e("Zstandard", ARC, &[0x28, 0xB5, 0x2F, 0xFD], Anchor::Anywhere, None),
    e("bzip2", ARC, b"BZh", Anchor::Anywhere, Some(v_bzip2)),
    e("XZ", ARC, &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], Anchor::Anywhere, None),
    e("7-Zip", ARC, &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], Anchor::Anywhere, None),
    e("ZIP", ARC, b"PK\x03\x04", Anchor::Anywhere, None),
    e("RAR", ARC, b"Rar!\x1A\x07", Anchor::Anywhere, None),
    e("tar (ustar)", ARC, b"ustar", Anchor::Anywhere, Some(v_tar)),
    // Certificates & crypto
    e("DER certificate (x509)", CRYPT, &[0x30, 0x82], Anchor::Anywhere, Some(v_der_cert)),
    e("DER PKCS#8 private key", CRYPT, &[0x30, 0x82], Anchor::Anywhere, Some(v_pkcs8)),
    e("DER PKCS#12 keystore", CRYPT, &[0x30, 0x82], Anchor::Anywhere, Some(v_pkcs12)),
    e("PEM certificate", CRYPT, b"-----BEGIN CERTIFICATE-----", Anchor::Anywhere, None),
    e("PEM private key", CRYPT, b"-----BEGIN PRIVATE KEY-----", Anchor::Anywhere, None),
    e("PEM encrypted private key", CRYPT, b"-----BEGIN ENCRYPTED PRIVATE KEY-----", Anchor::Anywhere, None),
    e("PEM RSA private key", CRYPT, b"-----BEGIN RSA PRIVATE KEY-----", Anchor::Anywhere, None),
    e("OpenSSH private key (PEM)", CRYPT, b"-----BEGIN OPENSSH PRIVATE KEY-----", Anchor::Anywhere, None),
    e("OpenSSH private key (raw)", CRYPT, b"openssh-key-v1\0", Anchor::Anywhere, None),
    e("Android OTA payload", CRYPT, b"CrAU", Anchor::Anywhere, Some(v_ota_payload)),
    // Media & misc
    e("PNG", MEDIA, &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], Anchor::Anywhere, None),
    e("JPEG", MEDIA, &[0xFF, 0xD8, 0xFF], Anchor::Anywhere, None),
    e("BMP", MEDIA, b"BM", Anchor::Anywhere, Some(v_bmp)),
    e("SQLite 3 database", MEDIA, b"SQLite format 3\0", Anchor::Anywhere, None),
    e("protobuf (heuristic)", MEDIA, &[0x0A], Anchor::FileOffset(0), Some(v_protobuf)),
    e("msgpack fixmap (heuristic)", MEDIA, &[0x82], Anchor::FileOffset(0), Some(v_msgpack)),
    e("msgpack fixarray (heuristic)", MEDIA, &[0x92], Anchor::FileOffset(0), Some(v_msgpack)),
];

/// Per-entry hit cap; 2-byte magics (zlib, JFFS2) recur endlessly in noise.
pub const MAX_HITS_PER_ENTRY: usize = 500;

/// Scan the whole buffer. Hits sorted by offset; bool = some entry truncated.
pub fn scan(data: &[u8]) -> (Vec<MagicHit>, bool) {
    let mut hits: Vec<MagicHit> = Vec::new();
    let mut truncated = false;

    // Anchored entries: direct check.
    // Anywhere entries: bucket by first byte for the linear sweep.
    let mut table: [Vec<usize>; 256] = std::array::from_fn(|_| Vec::new());
    for (i, entry) in MAGIC_TABLE.iter().enumerate() {
        match entry.anchor {
            Anchor::FileOffset(off) => {
                let off = off as usize;
                if data.len() >= off + entry.pattern.len()
                    && &data[off..off + entry.pattern.len()] == entry.pattern
                    && entry.validator.is_none_or(|v| v(data, off))
                {
                    hits.push(MagicHit {
                        offset: off as u64,
                        name: entry.name,
                        category: entry.category,
                    });
                }
            }
            Anchor::Anywhere => table[entry.pattern[0] as usize].push(i),
        }
    }

    let mut counts = vec![0usize; MAGIC_TABLE.len()];
    for (pos, &byte) in data.iter().enumerate() {
        for &ei in &table[byte as usize] {
            let entry = &MAGIC_TABLE[ei];
            if counts[ei] >= MAX_HITS_PER_ENTRY {
                truncated = true;
                continue;
            }
            if data.len() - pos >= entry.pattern.len()
                && &data[pos..pos + entry.pattern.len()] == entry.pattern
                && entry.validator.is_none_or(|v| v(data, pos))
            {
                hits.push(MagicHit {
                    offset: pos as u64,
                    name: entry.name,
                    category: entry.category,
                });
                counts[ei] += 1;
            }
        }
    }

    hits.sort_by_key(|h| h.offset);
    (hits, truncated)
}

/// Best-effort file type for the info bar: prefer a non-heuristic hit at
/// offset zero, else any hit at zero, else "data".
pub fn detect_type(hits: &[MagicHit]) -> String {
    let zero: Vec<&MagicHit> = hits.iter().filter(|h| h.offset == 0).collect();
    zero.iter()
        .find(|h| !h.name.contains("heuristic"))
        .or(zero.first())
        .map_or_else(|| "data".to_string(), |h| h.name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elf_detected_and_validated() {
        let mut data = b"\x7fELF\x02\x01\x01".to_vec();
        data.extend([0u8; 16]);
        let (hits, _) = scan(&data);
        assert!(hits.iter().any(|h| h.name == "ELF" && h.offset == 0));
        assert_eq!(detect_type(&hits), "ELF");
        // Bad class byte -> rejected
        let (hits2, _) = scan(b"\x7fELF\x09\x01\x01\0\0\0\0");
        assert!(hits2.iter().all(|h| h.name != "ELF"));
    }

    #[test]
    fn embedded_magics_found_at_offset() {
        let mut data = vec![0u8; 100];
        data.extend(&[0x1F, 0x8B, 0x08, 0x00]); // gzip at 100
        data.extend(vec![0u8; 50]);
        data.extend(b"hsqs"); // squashfs at 154
        data.extend(vec![0u8; 10]);
        let (hits, _) = scan(&data);
        assert!(hits.iter().any(|h| h.name == "gzip" && h.offset == 100));
        assert!(
            hits.iter()
                .any(|h| h.name.starts_with("SquashFS") && h.offset == 154)
        );
    }

    #[test]
    fn dex_versions() {
        for v in ["035", "036", "037", "038", "039"] {
            let data = format!("dex\n{v}\0rest").into_bytes();
            let (hits, _) = scan(&data);
            assert!(hits.iter().any(|h| h.name.starts_with("DEX")), "{v}");
        }
        let (hits, _) = scan(b"dex\n034\0rest");
        assert!(hits.iter().all(|h| !h.name.starts_with("DEX")));
    }

    #[test]
    fn pe_and_mz() {
        let mut data = vec![0u8; 0x100];
        data[0] = b'M';
        data[1] = b'Z';
        data[0x3C] = 0x80; // e_lfanew -> 0x80
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        data[0x84] = 0x64; // machine 0x8664
        data[0x85] = 0x86;
        let (hits, _) = scan(&data);
        assert!(hits.iter().any(|h| h.name.starts_with("MZ")));
        assert!(
            hits.iter()
                .any(|h| h.name == "PE header" && h.offset == 0x80)
        );
    }

    #[test]
    fn der_discrimination() {
        // x509-ish: 30 82 LL LL 30 82
        let (hits, _) = scan(&[0x30, 0x82, 0x01, 0x00, 0x30, 0x82, 0x00, 0xF0]);
        assert!(hits.iter().any(|h| h.name.contains("x509")));
        // pkcs8: 30 82 LL LL 02 01 00 30
        let (hits, _) = scan(&[0x30, 0x82, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30]);
        assert!(hits.iter().any(|h| h.name.contains("PKCS#8")));
        // random 30 82 with junk after: no hit
        let (hits, _) = scan(&[0x30, 0x82, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert!(hits.is_empty());
    }

    #[test]
    fn zlib_capped_not_starving() {
        // 600 zlib headers: capped at MAX_HITS_PER_ENTRY with truncation flag
        let mut data = Vec::new();
        for _ in 0..600 {
            data.extend(&[0x78, 0x9C, 0x00]);
        }
        let (hits, truncated) = scan(&data);
        assert!(truncated);
        assert_eq!(hits.len(), MAX_HITS_PER_ENTRY);
    }

    #[test]
    fn boot_image_and_friends() {
        let mut data = b"ANDROID!".to_vec();
        data.extend(vec![0u8; 64]);
        let (hits, _) = scan(&data);
        assert!(hits.iter().any(|h| h.name == "Android boot image"));
        assert_eq!(detect_type(&hits), "Android boot image");
    }
}
