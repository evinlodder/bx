//! Heuristic architecture pattern detection: function prologue/epilogue byte
//! signatures, NOP sleds, int3 runs, zero padding. Pure pattern matching —
//! no disassembly — so every result is labeled heuristic in the UI.

/// Masked byte: matches when `(input & mask) == value`.
#[derive(Clone, Copy)]
struct MByte {
    value: u8,
    mask: u8,
}

const fn b(value: u8) -> MByte {
    MByte { value, mask: 0xFF }
}
const fn m(value: u8, mask: u8) -> MByte {
    MByte { value, mask }
}

struct Signature {
    arch: &'static str,
    desc: &'static str,
    pat: &'static [MByte],
}

// Byte patterns assume the usual storage order for each ISA
// (little-endian words for ARM/AArch64/RISC-V; both endians for MIPS).
#[rustfmt::skip]
static SIGNATURES: &[Signature] = &[
    // x86 / x86_64
    Signature { arch: "x86_64", desc: "push rbp; mov rbp,rsp (prologue)", pat: &[b(0x55), b(0x48), b(0x89), b(0xE5)] },
    Signature { arch: "x86", desc: "push ebp; mov ebp,esp (prologue)", pat: &[b(0x55), b(0x89), b(0xE5)] },
    Signature { arch: "x86", desc: "ret (epilogue)", pat: &[b(0xC3)] },
    // ARM32 (LE byte order)
    Signature { arch: "ARM32", desc: "STMFD sp!, {..,lr} (prologue)", pat: &[m(0, 0), m(0x40, 0x40), b(0x2D), b(0xE9)] },
    Signature { arch: "ARM32", desc: "BX LR (epilogue)", pat: &[b(0x1E), b(0xFF), b(0x2F), b(0xE1)] },
    Signature { arch: "ARM32/Thumb", desc: "PUSH {..,LR} (prologue)", pat: &[m(0, 0), b(0xB5)] },
    Signature { arch: "ARM32/Thumb", desc: "BX LR (epilogue)", pat: &[b(0x70), b(0x47)] },
    // ARM64
    Signature { arch: "ARM64", desc: "STP X29,X30,[sp,..] (prologue)", pat: &[b(0xFD), b(0x7B), m(0, 0), b(0xA9)] },
    Signature { arch: "ARM64", desc: "RET (epilogue)", pat: &[b(0xC0), b(0x03), b(0x5F), b(0xD6)] },
    // MIPS, both endians: addiu sp,sp,-N then-or-near sw ra
    Signature { arch: "MIPS/BE", desc: "addiu sp,sp,-N (prologue)", pat: &[b(0x27), b(0xBD), b(0xFF), m(0, 0)] },
    Signature { arch: "MIPS/BE", desc: "sw ra, N(sp)", pat: &[b(0xAF), b(0xBF), m(0, 0), m(0, 0)] },
    Signature { arch: "MIPS/LE", desc: "addiu sp,sp,-N (prologue)", pat: &[m(0, 0), b(0xFF), b(0xBD), b(0x27)] },
    Signature { arch: "MIPS/LE", desc: "sw ra, N(sp)", pat: &[m(0, 0), m(0, 0), b(0xBF), b(0xAF)] },
    // PowerPC (BE)
    Signature { arch: "PPC", desc: "mflr r0 (prologue)", pat: &[b(0x7C), b(0x08), b(0x02), b(0xA6)] },
    Signature { arch: "PPC", desc: "stw r0, N(r1)", pat: &[b(0x90), b(0x01), b(0x00), m(0, 0)] },
    // RISC-V (LE): addi sp,sp,imm ; sd ra,off(sp)
    Signature { arch: "RISC-V", desc: "addi sp,sp,imm (prologue)", pat: &[b(0x13), b(0x01), m(0x01, 0x0F), m(0, 0)] },
    Signature { arch: "RISC-V", desc: "sd ra, off(sp)", pat: &[m(0x23, 0x7F), m(0x30, 0xF0), b(0x11), m(0, 0)] },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchHitKind {
    Prologue,
    Epilogue,
    NopSled,
    Int3Run,
    ZeroPad,
}

#[derive(Debug, Clone)]
pub struct ArchHit {
    pub start: u64,
    pub end: u64,
    pub arch: &'static str,
    pub desc: &'static str,
    pub kind: ArchHitKind,
}

/// Per-signature hit cap; lone-byte signatures (e.g. `C3`) fire constantly in
/// high-entropy data and must not starve the others.
pub const MAX_HITS_PER_SIG: usize = 10_000;

/// Scan the whole buffer. Returns hits sorted by start offset, plus a flag
/// signalling that a cap was reached (results truncated).
pub fn scan(data: &[u8]) -> (Vec<ArchHit>, bool) {
    let mut hits = Vec::new();

    // Index signatures by an anchor byte (first fully-masked element) so the
    // main loop is a table lookup per input byte.
    // (signature index, anchor position within pattern)
    let mut table: [Vec<(usize, usize)>; 256] = std::array::from_fn(|_| Vec::new());
    for (si, sig) in SIGNATURES.iter().enumerate() {
        let anchor = sig
            .pat
            .iter()
            .position(|mb| mb.mask == 0xFF)
            .expect("every signature needs one exact byte");
        table[sig.pat[anchor].value as usize].push((si, anchor));
    }

    let mut truncated = false;
    let mut sig_counts = vec![0usize; SIGNATURES.len()];
    for (i, &byte) in data.iter().enumerate() {
        for &(si, anchor) in &table[byte as usize] {
            if sig_counts[si] >= MAX_HITS_PER_SIG {
                truncated = true;
                continue;
            }
            let sig = &SIGNATURES[si];
            let Some(start) = i.checked_sub(anchor) else {
                continue;
            };
            if start + sig.pat.len() > data.len() {
                continue;
            }
            let ok = sig
                .pat
                .iter()
                .zip(&data[start..])
                .all(|(mb, &d)| d & mb.mask == mb.value);
            if ok {
                let kind = if sig.desc.contains("epilogue") {
                    ArchHitKind::Epilogue
                } else {
                    ArchHitKind::Prologue
                };
                hits.push(ArchHit {
                    start: start as u64,
                    end: (start + sig.pat.len()) as u64,
                    arch: sig.arch,
                    desc: sig.desc,
                    kind,
                });
                sig_counts[si] += 1;
            }
        }
    }

    // Byte-run detectors: NOP sleds, int3 runs, zero padding.
    for (byte, min_len, arch, desc, kind) in [
        (0x90u8, 8usize, "x86", "NOP sled", ArchHitKind::NopSled),
        (0xCC, 4, "x86", "int3 run", ArchHitKind::Int3Run),
        (0x00, 16, "-", "zero-filled padding", ArchHitKind::ZeroPad),
    ] {
        let mut i = 0;
        while i < data.len() {
            if data[i] == byte {
                let run_start = i;
                while i < data.len() && data[i] == byte {
                    i += 1;
                }
                if i - run_start >= min_len {
                    hits.push(ArchHit {
                        start: run_start as u64,
                        end: i as u64,
                        arch,
                        desc,
                        kind,
                    });
                }
            } else {
                i += 1;
            }
        }
    }

    hits.sort_by_key(|h| (h.start, h.end));
    (hits, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hit_with_desc<'a>(hits: &'a [ArchHit], frag: &str) -> Option<&'a ArchHit> {
        hits.iter().find(|h| h.desc.contains(frag))
    }

    #[test]
    fn x86_prologues() {
        let data = [0x00, 0x55, 0x48, 0x89, 0xE5, 0x00, 0x55, 0x89, 0xE5];
        let (hits, _) = scan(&data);
        assert_eq!(hit_with_desc(&hits, "push rbp").unwrap().start, 1);
        // x86-32 prologue is also embedded inside the x64 one at offset 2.. no:
        // 48 89 E5 doesn't begin with 55. The standalone one is at 6.
        assert!(
            hits.iter()
                .any(|h| h.desc.contains("push ebp") && h.start == 6)
        );
    }

    #[test]
    fn arm_signatures() {
        // STMFD sp!,{r4,lr} = E92D4010 -> LE 10 40 2D E9 ; BX LR = 1E FF 2F E1
        let data = [
            0x10, 0x40, 0x2D, 0xE9, 0x1E, 0xFF, 0x2F, 0xE1, 0x10, 0xB5, 0x70, 0x47,
        ];
        let (hits, _) = scan(&data);
        assert!(hit_with_desc(&hits, "STMFD").is_some());
        assert!(
            hits.iter()
                .any(|h| h.desc.contains("BX LR") && h.arch == "ARM32")
        );
        assert!(
            hits.iter()
                .any(|h| h.desc.contains("PUSH {..,LR}") && h.start == 8)
        );
        assert!(
            hits.iter()
                .any(|h| h.arch == "ARM32/Thumb" && h.desc.contains("BX LR"))
        );
        // STMFD without LR bit must NOT match: E92D0010 -> 10 00 2D E9
        let (hits2, _) = scan(&[0x10, 0x00, 0x2D, 0xE9]);
        assert!(hit_with_desc(&hits2, "STMFD").is_none());
    }

    #[test]
    fn arm64_and_riscv() {
        // stp x29,x30,[sp,#-16]! = A9BF7BFD -> FD 7B BF A9 ; ret = C0 03 5F D6
        // addi sp,sp,-32 = FE010113 -> 13 01 01 FE ; sd ra,24(sp) = 00113C23 -> 23 3C 11 00
        let data = [
            0xFD, 0x7B, 0xBF, 0xA9, 0xC0, 0x03, 0x5F, 0xD6, 0x13, 0x01, 0x01, 0xFE, 0x23, 0x3C,
            0x11, 0x00,
        ];
        let (hits, _) = scan(&data);
        assert!(hit_with_desc(&hits, "STP X29").is_some());
        assert!(hit_with_desc(&hits, "RET").is_some());
        assert!(hit_with_desc(&hits, "addi sp,sp").is_some());
        assert!(hit_with_desc(&hits, "sd ra").is_some());
    }

    #[test]
    fn mips_ppc() {
        let data = [
            0x27, 0xBD, 0xFF, 0xE0, // addiu sp,sp,-32 BE
            0xAF, 0xBF, 0x00, 0x1C, // sw ra,28(sp) BE
            0xE0, 0xFF, 0xBD, 0x27, // addiu LE
            0x7C, 0x08, 0x02, 0xA6, // mflr r0
            0x90, 0x01, 0x00, 0x24, // stw r0,36(r1)
        ];
        let (hits, _) = scan(&data);
        assert!(
            hits.iter()
                .any(|h| h.arch == "MIPS/BE" && h.desc.contains("addiu"))
        );
        assert!(
            hits.iter()
                .any(|h| h.arch == "MIPS/BE" && h.desc.contains("sw ra"))
        );
        assert!(
            hits.iter()
                .any(|h| h.arch == "MIPS/LE" && h.desc.contains("addiu"))
        );
        assert!(
            hits.iter()
                .any(|h| h.arch == "PPC" && h.desc.contains("mflr"))
        );
        assert!(
            hits.iter()
                .any(|h| h.arch == "PPC" && h.desc.contains("stw r0"))
        );
    }

    #[test]
    fn runs() {
        let mut data = vec![0x90u8; 10];
        data.extend([0xCC; 5]);
        data.extend([0xAA]); // breaker
        data.extend([0x00; 20]);
        let (hits, _) = scan(&data);
        let nop = hits
            .iter()
            .find(|h| h.kind == ArchHitKind::NopSled)
            .unwrap();
        assert_eq!((nop.start, nop.end), (0, 10));
        let int3 = hits
            .iter()
            .find(|h| h.kind == ArchHitKind::Int3Run)
            .unwrap();
        assert_eq!((int3.start, int3.end), (10, 15));
        let zero = hits
            .iter()
            .find(|h| h.kind == ArchHitKind::ZeroPad)
            .unwrap();
        assert_eq!((zero.start, zero.end), (16, 36));
        // short runs don't fire
        let (hits2, _) = scan(&[0x90u8; 7]);
        assert!(hits2.iter().all(|h| h.kind != ArchHitKind::NopSled));
    }
}
