//! Positional byte diff between two buffers, grouped into hunks.
//!
//! This is an offset-aligned compare (right for patched firmware images),
//! not a content-tracking diff: bytes past the shorter file's end are one
//! Added (other file longer) or Removed (other file shorter) hunk.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HunkKind {
    Changed,
    /// Present only in the second file (it is longer).
    Added,
    /// Present only in the first file (second is shorter).
    Removed,
}

#[derive(Debug, Clone, Copy)]
pub struct Hunk {
    pub start: u64,
    pub end: u64,
    pub kind: HunkKind,
}

/// Byte runs that differ, merging runs separated by fewer than `gap` equal
/// bytes so a sprinkle of changes reads as one hunk.
pub fn compute(a: &[u8], b: &[u8], gap: usize) -> Vec<Hunk> {
    let common = a.len().min(b.len());
    let mut hunks: Vec<Hunk> = Vec::new();
    let mut i = 0;
    while i < common {
        if a[i] != b[i] {
            let start = i;
            let mut last_diff = i;
            i += 1;
            while i < common && i - last_diff <= gap {
                if a[i] != b[i] {
                    last_diff = i;
                }
                i += 1;
            }
            hunks.push(Hunk {
                start: start as u64,
                end: (last_diff + 1) as u64,
                kind: HunkKind::Changed,
            });
            i = last_diff + 1;
        } else {
            i += 1;
        }
    }
    use std::cmp::Ordering;
    match a.len().cmp(&b.len()) {
        Ordering::Less => hunks.push(Hunk {
            start: common as u64,
            end: b.len() as u64,
            kind: HunkKind::Added,
        }),
        Ordering::Greater => hunks.push(Hunk {
            start: common as u64,
            end: a.len() as u64,
            kind: HunkKind::Removed,
        }),
        Ordering::Equal => {}
    }
    hunks
}

/// Hunk containing or nearest after `offset` (for n), wrapped.
pub fn next_hunk(hunks: &[Hunk], offset: u64) -> Option<&Hunk> {
    if hunks.is_empty() {
        return None;
    }
    hunks.iter().find(|h| h.start > offset).or(hunks.first())
}

pub fn prev_hunk(hunks: &[Hunk], offset: u64) -> Option<&Hunk> {
    if hunks.is_empty() {
        return None;
    }
    hunks
        .iter()
        .rev()
        .find(|h| h.start < offset)
        .or(hunks.last())
}

pub fn hunk_at(hunks: &[Hunk], offset: u64) -> Option<&Hunk> {
    let idx = hunks.partition_point(|h| h.start <= offset);
    idx.checked_sub(1)
        .map(|i| &hunks[i])
        .filter(|h| offset < h.end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn three_hunks() {
        let a = [0u8; 32];
        let mut b = a;
        b[2] = 1;
        b[3] = 1;
        b[16] = 1;
        b[30] = 1;
        let hunks = compute(&a, &b, 3);
        assert_eq!(hunks.len(), 3);
        assert_eq!((hunks[0].start, hunks[0].end), (2, 4));
        assert_eq!((hunks[1].start, hunks[1].end), (16, 17));
        assert_eq!((hunks[2].start, hunks[2].end), (30, 31));
    }

    #[test]
    fn gap_merging() {
        let a = [0u8; 10];
        let mut b = a;
        b[2] = 1;
        b[5] = 1; // 2 equal bytes apart -> merged with gap=3
        let hunks = compute(&a, &b, 3);
        assert_eq!(hunks.len(), 1);
        assert_eq!((hunks[0].start, hunks[0].end), (2, 6));
    }

    #[test]
    fn length_mismatch() {
        let hunks = compute(&[1, 2], &[1, 2, 3, 4], 0);
        assert_eq!(hunks.len(), 1);
        assert_eq!(hunks[0].kind, HunkKind::Added);
        assert_eq!((hunks[0].start, hunks[0].end), (2, 4));
        let hunks = compute(&[1, 2, 3], &[1], 0);
        assert_eq!(hunks[0].kind, HunkKind::Removed);
    }

    #[test]
    fn navigation_wraps() {
        let hunks = compute(&[0u8, 0, 0, 0, 0], &[1u8, 0, 0, 0, 1], 0);
        assert_eq!(hunks.len(), 2);
        assert_eq!(next_hunk(&hunks, 0).unwrap().start, 4);
        assert_eq!(next_hunk(&hunks, 4).unwrap().start, 0); // wrap
        assert_eq!(prev_hunk(&hunks, 4).unwrap().start, 0);
        assert_eq!(prev_hunk(&hunks, 0).unwrap().start, 4); // wrap
        assert!(hunk_at(&hunks, 0).is_some());
        assert!(hunk_at(&hunks, 2).is_none());
    }
}
