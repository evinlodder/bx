//! Shannon entropy, whole-file and per-bucket for the in-pane bar graph.

/// Shannon entropy in bits per byte (0.0 ..= 8.0).
pub fn shannon(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// Split `data` into `buckets` roughly equal chunks and compute entropy of
/// each. Returns (bucket_start_offset, entropy) pairs.
pub fn bucketed(data: &[u8], buckets: usize) -> Vec<(u64, f64)> {
    if data.is_empty() || buckets == 0 {
        return Vec::new();
    }
    let size = data.len().div_ceil(buckets).max(1);
    data.chunks(size)
        .enumerate()
        .map(|(i, chunk)| ((i * size) as u64, shannon(chunk)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeros_have_no_entropy() {
        assert_eq!(shannon(&[0u8; 1024]), 0.0);
    }

    #[test]
    fn uniform_is_eight_bits() {
        let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        let h = shannon(&data);
        assert!((h - 8.0).abs() < 1e-9, "h = {h}");
    }

    #[test]
    fn two_symbols_one_bit() {
        let data: Vec<u8> = [0u8, 1].iter().cycle().take(1000).copied().collect();
        let h = shannon(&data);
        assert!((h - 1.0).abs() < 1e-9, "h = {h}");
    }

    #[test]
    fn buckets_cover_file() {
        let data = vec![0u8; 100];
        let b = bucketed(&data, 10);
        assert_eq!(b.len(), 10);
        assert_eq!(b[0].0, 0);
        assert_eq!(b[9].0, 90);
    }
}
