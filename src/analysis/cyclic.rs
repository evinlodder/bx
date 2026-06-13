//! Repeating-structure (cyclic pattern) detection via byte autocorrelation.

pub struct CyclicHit {
    pub period: usize,
    /// Fraction of positions where data[i] == data[i + period].
    pub score: f64,
}

/// Test candidate periods and report ones whose self-similarity exceeds
/// `threshold` (e.g. 0.90). Constant regions (period 1) are reported too —
/// callers may want to label them as fill instead.
pub fn detect(data: &[u8], max_period: usize, threshold: f64) -> Vec<CyclicHit> {
    let mut hits = Vec::new();
    if data.len() < 8 {
        return hits;
    }
    let max_p = max_period.min(data.len() / 2);
    for p in 1..=max_p {
        let pairs = data.len() - p;
        let matches = (0..pairs).filter(|&i| data[i] == data[i + p]).count();
        let score = matches as f64 / pairs as f64;
        if score >= threshold {
            // Skip multiples of an already-found period; they're implied.
            if hits
                .iter()
                .any(|h: &CyclicHit| p % h.period == 0 && h.score >= threshold)
            {
                continue;
            }
            hits.push(CyclicHit { period: p, score });
        }
    }
    hits.sort_by(|a, b| b.score.total_cmp(&a.score));
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_period_four() {
        let data: Vec<u8> = [0xDE, 0xAD, 0xBE, 0xEF]
            .iter()
            .cycle()
            .take(256)
            .copied()
            .collect();
        let hits = detect(&data, 64, 0.95);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].period, 4);
        assert!(hits[0].score > 0.99);
    }

    #[test]
    fn skips_multiples() {
        let data: Vec<u8> = [1u8, 2].iter().cycle().take(200).copied().collect();
        let hits = detect(&data, 16, 0.95);
        assert_eq!(hits.iter().filter(|h| h.period % 2 == 0).count(), 1);
    }

    #[test]
    fn random_data_no_hits() {
        let data: Vec<u8> = (0..512u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
            .collect();
        assert!(detect(&data, 64, 0.9).is_empty());
    }
}
