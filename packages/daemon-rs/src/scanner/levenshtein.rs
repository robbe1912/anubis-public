//! Levenshtein distance helpers — extracted from forge_pipeline.rs (M1 chunk 3).
//!
//! Two variants:
//!   - `capped(a, b, cap)` — early-exits when distance exceeds cap. Use when
//!     you only care whether distance ≤ cap (cheaper for long strings).
//!   - `distance(a, b)` — full Levenshtein. Use for short strings where the
//!     cap-based early exit provides no benefit.

/// Levenshtein distance with early exit. Returns `cap + 1` if the actual
/// distance exceeds `cap`, otherwise the actual distance.
pub(crate) fn capped(a: &str, b: &str, cap: usize) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 { return n; }
    if n == 0 { return m; }
    if m.abs_diff(n) > cap { return cap + 1; }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        if curr.iter().all(|&x| x > cap) { return cap + 1; }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

/// Simple Levenshtein distance (for short strings like namespace names).
pub(crate) fn distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 { return n; }
    if n == 0 { return m; }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr: Vec<usize> = vec![0; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capped_returns_actual_distance_when_within_cap() {
        assert_eq!(capped("cat", "cot", 3), 1);
        assert_eq!(capped("kitten", "sitting", 3), 3);
    }

    #[test]
    fn capped_returns_cap_plus_one_when_exceeded() {
        // distance is 5, cap is 3 → returns 4 (cap + 1)
        assert_eq!(capped("abcde", "xyz", 3), 4);
    }

    #[test]
    fn capped_returns_length_diff_when_exceeds_cap() {
        // |5-1| = 4 > cap 3 → early exit
        assert_eq!(capped("hello", "x", 3), 4);
    }

    #[test]
    fn distance_returns_full_levenshtein() {
        assert_eq!(distance("cat", "cot"), 1);
        assert_eq!(distance("kitten", "sitting"), 3);
        assert_eq!(distance("", "abc"), 3);
        assert_eq!(distance("abc", ""), 3);
    }

    #[test]
    fn distance_is_symmetric() {
        assert_eq!(distance("foo", "bar"), distance("bar", "foo"));
    }
}
