//! Single-byte XOR brute force over a selected region.

pub struct XorHit {
    pub key: u8,
    /// Fraction of decoded bytes that are printable ASCII.
    pub printable_ratio: f64,
    /// Fraction that decode to letters/digits/space — many keys yield 100%
    /// printable junk, so ranking needs a text-likeness signal too.
    pub text_ratio: f64,
    pub preview: String,
}

fn is_printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t' || b == b'\r'
}

fn is_texty(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b' '
}

/// Try keys 0x00-0xFF; return hits above `min_ratio` printable, best first.
/// Key 0x00 (identity) is included so an already-printable region is obvious.
pub fn brute_force(data: &[u8], min_ratio: f64) -> Vec<XorHit> {
    let mut hits = Vec::new();
    if data.is_empty() {
        return hits;
    }
    for key in 0..=255u8 {
        let printable = data.iter().filter(|&&b| is_printable(b ^ key)).count();
        let texty = data.iter().filter(|&&b| is_texty(b ^ key)).count();
        let ratio = printable as f64 / data.len() as f64;
        let text_ratio = texty as f64 / data.len() as f64;
        if ratio >= min_ratio {
            let preview: String = data
                .iter()
                .take(48)
                .map(|&b| {
                    let d = b ^ key;
                    if (0x20..0x7f).contains(&d) {
                        d as char
                    } else {
                        '.'
                    }
                })
                .collect();
            hits.push(XorHit {
                key,
                printable_ratio: ratio,
                text_ratio,
                preview,
            });
        }
    }
    hits.sort_by(|a, b| {
        (b.text_ratio + b.printable_ratio).total_cmp(&(a.text_ratio + a.printable_ratio))
    });
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_known_key() {
        let plain = b"The quick brown fox jumps over the lazy dog";
        let key = 0x5A;
        let enc: Vec<u8> = plain.iter().map(|b| b ^ key).collect();
        let hits = brute_force(&enc, 0.9);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].key, key);
        assert!(hits[0].preview.starts_with("The quick"));
    }

    #[test]
    fn random_binary_gives_few_hits() {
        // Deterministic pseudo-random junk.
        let data: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        let hits = brute_force(&data, 0.95);
        assert!(hits.len() < 3, "{} hits", hits.len());
    }
}
