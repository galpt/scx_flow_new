// SPDX-License-Identifier: GPL-2.0
//! Flat hint table for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the flat period hint table as mirror oracle. The table maps
//! task identifiers to periods derived from task weight. Light shares
//! map to long periods and heavy shares map to short periods. Full
//! tables keep the default period for fresh identifiers. Core derives
//! periods directly from weight with the mirror kept for tests plus
//! observability solely. Hierarchy tracking stays out, so hints stay
//! derived, not hierarchy bound.

use std::collections::HashMap;

/// Max hint rows bound shared with the BPF header.
pub const HINT_MAX: u64 = 4096;
/// Cap for stored rows in the userspace mirror.
pub const HINT_CAP: usize = 4096;

/// Period hint in micros for one weight with a fixed table.
/// Light shares map to long periods and heavy shares map to short
/// periods. The hint tunes admission through the period alone.
pub fn hint_period_us(weight: u32) -> u64 {
    let w = super::slice::clamp_weight(weight);
    if w < 64 {
        32_000
    } else if w < 128 {
        16_000
    } else if w < 512 {
        8_000
    } else {
        4_000
    }
}

/// Flat hint table keyed by task identifier.
/// Holds at most cap rows. Fresh identifiers miss to zero and the
/// caller falls back to the default period. Keys name tasks, not
/// hierarchy groups.
pub struct HintTable {
    rows: HashMap<u64, u64>,
    cap: usize,
}

impl HintTable {
    /// Empty table with the default cap.
    pub fn new() -> Self {
        Self {
            rows: HashMap::new(),
            cap: HINT_CAP,
        }
    }

    /// Empty table with a custom cap for tests.
    #[cfg(test)]
    pub fn with_cap(cap: usize) -> Self {
        Self {
            rows: HashMap::new(),
            cap,
        }
    }

    /// Row count now held.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// True when the table holds zero rows.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Insert or refresh one hint row.
    /// Returns false when the table is full and the identifier is fresh.
    /// Fresh misses keep the default period at the caller.
    pub fn insert(&mut self, id: u64, period_us: u64) -> bool {
        if id == 0 {
            return false;
        }
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.rows.entry(id) {
            e.insert(period_us);
            return true;
        }
        if self.rows.len() >= self.cap {
            return false;
        }
        self.rows.insert(id, period_us);
        true
    }

    /// Remove one hint row. Missing identifiers pass through.
    #[cfg(test)]
    pub fn remove(&mut self, id: u64) {
        self.rows.remove(&id);
    }

    /// Period hint in micros for one identifier with zero for miss.
    /// Misses use the default period at the caller.
    pub fn lookup(&self, id: u64) -> u64 {
        if id == 0 {
            return 0;
        }
        self.rows.get(&id).copied().unwrap_or(0)
    }
}

impl Default for HintTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_maps_light_long_heavy_short() {
        assert_eq!(hint_period_us(1), 32_000);
        assert_eq!(hint_period_us(100), 16_000);
        assert_eq!(hint_period_us(200), 8_000);
        assert_eq!(hint_period_us(1000), 4_000);
    }

    #[test]
    fn insert_lookup_remove_round_trip() {
        let mut t = HintTable::new();
        assert!(t.is_empty());
        assert!(t.insert(7, 8000));
        assert_eq!(t.lookup(7), 8000);
        assert_eq!(t.len(), 1);
        t.remove(7);
        assert_eq!(t.lookup(7), 0);
    }

    #[test]
    fn full_table_keeps_default_for_fresh() {
        let mut t = HintTable::with_cap(1);
        assert!(t.insert(1, 8000));
        assert!(!t.insert(2, 8000));
        assert_eq!(t.lookup(2), 0);
        assert!(t.insert(1, 4000));
        assert_eq!(t.lookup(1), 4000);
    }

    #[test]
    fn zero_identifier_misses() {
        let mut t = HintTable::new();
        assert!(!t.insert(0, 8000));
        assert_eq!(t.lookup(0), 0);
    }
}
