//! Sorted, disjoint address ranges, each owned by the first rule that covered it.

use crate::{Action, Coverage};

/// Integer representation of an address family.
pub(crate) trait Bits: Copy + Ord + std::fmt::Debug {
    fn checked_inc(self) -> Option<Self>;
    fn dec(self) -> Self;
}

macro_rules! impl_bits {
    ($($t:ty),*) => {$(
        impl Bits for $t {
            fn checked_inc(self) -> Option<Self> {
                self.checked_add(1)
            }
            fn dec(self) -> Self {
                self - 1
            }
        }
    )*};
}
impl_bits!(u32, u128);

/// Inclusive range `[start, end]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Range<T> {
    start: T,
    end: T,
    action: Action,
}

#[derive(Debug, Clone)]
pub(crate) struct Ranges<T> {
    /// Sorted by `start`, non-overlapping, and no two touching neighbours share an action.
    entries: Vec<Range<T>>,
}

impl<T> Default for Ranges<T> {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
        }
    }
}

impl<T: Bits> Ranges<T> {
    /// Claim whatever part of `[start, end]` is not already owned by an earlier rule.
    pub(crate) fn push(&mut self, start: T, end: T, action: Action) -> Coverage {
        debug_assert!(start <= end);
        // Overlapped entries are `entries[lo..hi]`.
        let lo = self.entries.partition_point(|r| r.end < start);
        let hi = lo + self.entries[lo..].partition_point(|r| r.start <= end);

        let mut gaps = Vec::new();
        let mut cursor = Some(start);
        let mut conflict = false;
        for r in &self.entries[lo..hi] {
            let Some(c) = cursor else { break };
            if r.start > c {
                gaps.push(Range {
                    start: c,
                    end: r.start.dec(),
                    action,
                });
            }
            conflict |= r.action != action;
            cursor = r.end.checked_inc();
        }
        if let Some(c) = cursor
            && c <= end
        {
            gaps.push(Range {
                start: c,
                end,
                action,
            });
        }

        if gaps.is_empty() {
            return if conflict {
                Coverage::Conflicting
            } else {
                Coverage::Redundant
            };
        }

        // Rebuild the affected window, including one neighbour on each side so new gaps can
        // merge with touching ranges of the same action.
        let win_lo = lo.saturating_sub(1);
        let win_hi = (hi + 1).min(self.entries.len());
        let mut merged: Vec<Range<T>> = Vec::with_capacity(win_hi - win_lo + gaps.len());
        let mut old = self.entries[win_lo..win_hi].iter().copied().peekable();
        let mut new = gaps.into_iter().peekable();
        loop {
            let next = match (old.peek(), new.peek()) {
                (Some(o), Some(n)) if o.start < n.start => old.next(),
                (Some(_), None) => old.next(),
                (_, Some(_)) => new.next(),
                (None, None) => break,
            };
            let next = next.unwrap();
            match merged.last_mut() {
                Some(last)
                    if last.action == next.action && last.end.checked_inc() == Some(next.start) =>
                {
                    last.end = next.end;
                }
                _ => merged.push(next),
            }
        }
        self.entries.splice(win_lo..win_hi, merged);
        Coverage::Effective
    }

    pub(crate) fn lookup(&self, ip: T) -> Option<Action> {
        let idx = self.entries.partition_point(|r| r.start <= ip);
        let r = self.entries.get(idx.checked_sub(1)?)?;
        (r.end >= ip).then_some(r.action)
    }

    #[cfg(test)]
    fn check_invariants(&self) {
        for w in self.entries.windows(2) {
            assert!(w[0].start <= w[0].end);
            assert!(w[0].end < w[1].start, "overlap: {w:?}");
            if w[0].end.checked_inc() == Some(w[1].start) {
                assert_ne!(w[0].action, w[1].action, "unmerged: {w:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use Action::{Allow, Deny};

    fn ranges(r: &Ranges<u32>) -> Vec<(u32, u32, Action)> {
        r.check_invariants();
        r.entries
            .iter()
            .map(|r| (r.start, r.end, r.action))
            .collect()
    }

    #[test]
    fn fills_gaps_only() {
        let mut r = Ranges::<u32>::default();
        assert_eq!(r.push(10, 19, Deny), Coverage::Effective);
        assert_eq!(r.push(30, 39, Deny), Coverage::Effective);
        assert_eq!(r.push(0, 50, Allow), Coverage::Effective);
        assert_eq!(
            ranges(&r),
            [
                (0, 9, Allow),
                (10, 19, Deny),
                (20, 29, Allow),
                (30, 39, Deny),
                (40, 50, Allow)
            ]
        );
    }

    #[test]
    fn merges_touching_same_action() {
        let mut r = Ranges::<u32>::default();
        r.push(0, 9, Allow);
        r.push(20, 29, Allow);
        r.push(10, 19, Allow);
        assert_eq!(ranges(&r), [(0, 29, Allow)]);
    }

    #[test]
    fn coverage() {
        let mut r = Ranges::<u32>::default();
        r.push(0, 9, Allow);
        r.push(10, 19, Allow);
        assert_eq!(r.push(0, 19, Allow), Coverage::Redundant);
        assert_eq!(r.push(5, 5, Allow), Coverage::Redundant);
        assert_eq!(r.push(5, 5, Deny), Coverage::Conflicting);
        r.push(20, 29, Deny);
        assert_eq!(r.push(15, 25, Allow), Coverage::Conflicting);
        assert_eq!(r.push(15, 30, Allow), Coverage::Effective);
    }

    #[test]
    fn full_space_edges() {
        let mut r = Ranges::<u32>::default();
        assert_eq!(r.push(u32::MAX, u32::MAX, Deny), Coverage::Effective);
        assert_eq!(r.push(0, u32::MAX, Allow), Coverage::Effective);
        assert_eq!(
            ranges(&r),
            [(0, u32::MAX - 1, Allow), (u32::MAX, u32::MAX, Deny)]
        );
        assert_eq!(r.push(0, u32::MAX, Deny), Coverage::Conflicting);
        assert_eq!(r.lookup(0), Some(Allow));
        assert_eq!(r.lookup(u32::MAX), Some(Deny));
    }

    #[test]
    fn lookup_misses() {
        let mut r = Ranges::<u32>::default();
        assert_eq!(r.lookup(5), None);
        r.push(10, 19, Allow);
        assert_eq!(r.lookup(9), None);
        assert_eq!(r.lookup(10), Some(Allow));
        assert_eq!(r.lookup(19), Some(Allow));
        assert_eq!(r.lookup(20), None);
    }
}
