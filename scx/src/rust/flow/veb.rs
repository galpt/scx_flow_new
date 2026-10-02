// SPDX-License-Identifier: GPL-2.0
//! Quantized order for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the quantized order as mirror oracle. Deadlines quantize to
//! a small key. Each key holds one FIFO queue. The tree finds the least
//! key in doubly logarithmic time. Equal keys leave in insert order.
//! Core owns order with the mirror kept for tests plus observability
//! solely with identical quantize plus duplicate plus remove math.

use std::collections::HashMap;
use std::collections::VecDeque;

/// Universe size at sixty five thousand five hundred thirty six keys.
pub const VEB_U: usize = 65536;
/// Mask for quantized keys.
pub const VEB_MASK: u64 = 65535;
/// Shift from nanos to keys at one thousand twenty four nanos per step.
pub const QUANT_SHIFT: u32 = 10;

/// Quantize one deadline in nanos to one tree key.
/// Monotonic growth maps to monotonic keys. Large values saturate at
/// the top key and leave in insert order there.
pub fn quantize(deadline: u64) -> u16 {
    (deadline >> QUANT_SHIFT).min(VEB_MASK) as u16
}

/// Entry held per queued task.
/// Pid names the task. Deadline keeps the absolute deadline for debug.
/// Seq breaks ties toward the earlier arrival across keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlowEntry {
    /// Task identifier.
    pub pid: u32,
    /// Absolute deadline in nanos.
    pub deadline: u64,
    /// Arrival sequence for stable order.
    pub seq: u64,
}

fn sqrt_u(u: usize) -> usize {
    let bits = u.ilog2() as usize;
    1usize << bits.div_ceil(2)
}

fn high(x: u16, s: usize) -> usize {
    (x as usize) / s
}

fn low(x: u16, s: usize) -> usize {
    (x as usize) % s
}

fn index(h: usize, l: usize, s: usize) -> u16 {
    (h * s + l) as u16
}

/// Recursive tree over a power of two universe.
/// Min holds the least member. Max holds the greatest member. Summary
/// tracks live clusters. Clusters hold the low parts per high part.
/// Empty clusters stay absent and the summary stays tight.
pub struct Veb {
    u: usize,
    sq: usize,
    min: Option<u16>,
    max: Option<u16>,
    summary: Option<Box<Veb>>,
    clusters: Vec<Option<Box<Veb>>>,
}

impl Veb {
    /// Empty tree over the given universe.
    /// The universe stays a power of two from two upward.
    pub fn new(u: usize) -> Self {
        assert!(u >= 2 && u.is_power_of_two());
        if u == 2 {
            return Self {
                u,
                sq: 2,
                min: None,
                max: None,
                summary: None,
                clusters: Vec::new(),
            };
        }
        let sq = sqrt_u(u);
        let mut clusters = Vec::with_capacity(sq);
        clusters.resize_with(sq, || None);
        Self {
            u,
            sq,
            min: None,
            max: None,
            summary: Some(Box::new(Veb::new(sq))),
            clusters,
        }
    }

    /// True when the tree holds zero keys.
    pub fn is_empty(&self) -> bool {
        self.min.is_none()
    }

    /// Least key held with empty for vacant trees.
    pub fn min(&self) -> Option<u16> {
        self.min
    }

    /// Greatest key held with empty for vacant trees.
    pub fn max(&self) -> Option<u16> {
        self.max
    }

    /// Tree height in levels. The full universe spans five levels.
    #[cfg(test)]
    pub fn height(&self) -> usize {
        if self.u <= 2 {
            return 1;
        }
        1 + self.summary.as_ref().map(|s| s.height()).unwrap_or(1)
    }

    /// Insert one key. Duplicate inserts pass through.
    /// Corrupt state returns early in release plus asserts in debug.
    pub fn insert(&mut self, x: u16) {
        if self.min.is_none() {
            self.min = Some(x);
            self.max = Some(x);
            return;
        }
        debug_assert!(self.min.is_some());
        debug_assert!(self.max.is_some());
        let Some(cur_min) = self.min else {
            return;
        };
        let Some(cur_max) = self.max else {
            return;
        };
        let mut v = x;
        if v < cur_min {
            let old = self.min.replace(v);
            debug_assert!(old.is_some());
            let Some(prev) = old else {
                return;
            };
            v = prev;
        }
        if self.u == 2 {
            if v > cur_max {
                self.max = Some(v);
            }
            return;
        }
        let h = high(v, self.sq);
        let l = low(v, self.sq);
        if h >= self.clusters.len() {
            debug_assert!(false);
            return;
        }
        let need = match &self.clusters[h] {
            None => true,
            Some(c) => c.is_empty(),
        };
        if need {
            if self.clusters[h].is_none() {
                self.clusters[h] = Some(Box::new(Veb::new(self.sq)));
            }
            debug_assert!(self.summary.is_some());
            let Some(sum) = self.summary.as_mut() else {
                return;
            };
            sum.insert(h as u16);
            let Some(cluster) = self.clusters[h].as_mut() else {
                debug_assert!(false);
                return;
            };
            cluster.insert(l as u16);
        } else {
            let Some(cluster) = self.clusters[h].as_mut() else {
                debug_assert!(false);
                return;
            };
            cluster.insert(l as u16);
        }
        if v > cur_max {
            self.max = Some(v);
        }
    }

    /// Remove one key. Missing keys pass through.
    /// Returns true when the key was held.
    /// Corrupt state returns false in release plus asserts in debug.
    pub fn remove(&mut self, x: u16) -> bool {
        if self.min.is_none() {
            return false;
        }
        if self.min == self.max {
            if self.min == Some(x) {
                self.min = None;
                self.max = None;
                return true;
            }
            return false;
        }
        if self.u == 2 {
            if Some(x) == self.min {
                self.min = self.max;
                return true;
            }
            if Some(x) == self.max {
                self.max = self.min;
                return true;
            }
            return false;
        }
        let mut v = x;
        if Some(v) == self.min {
            debug_assert!(self.summary.is_some());
            let Some(sum) = self.summary.as_ref() else {
                debug_assert!(false);
                return false;
            };
            let first = match sum.min() {
                Some(f) => f as usize,
                None => return false,
            };
            if first >= self.clusters.len() {
                debug_assert!(false);
                return false;
            }
            let Some(cluster) = self.clusters[first].as_ref() else {
                debug_assert!(false);
                return false;
            };
            let Some(inner) = cluster.min() else {
                debug_assert!(false);
                return false;
            };
            let nxt = index(first, inner as usize, self.sq);
            self.min = Some(nxt);
            v = nxt;
        }
        let h = high(v, self.sq);
        let l = low(v, self.sq);
        let present = match self.clusters.get_mut(h) {
            Some(slot) => match slot.as_mut() {
                Some(c) => c.remove(l as u16),
                None => false,
            },
            None => false,
        };
        if !present && Some(x) != self.max {
            return false;
        }
        let empty = match self.clusters.get(h) {
            None => true,
            Some(None) => true,
            Some(Some(c)) => c.is_empty(),
        };
        if empty {
            if h >= self.clusters.len() {
                debug_assert!(false);
                return false;
            }
            self.clusters[h] = None;
            debug_assert!(self.summary.is_some());
            let Some(sum) = self.summary.as_mut() else {
                debug_assert!(false);
                return false;
            };
            sum.remove(h as u16);
        }
        if Some(v) == self.max || Some(x) == self.max {
            debug_assert!(self.summary.is_some());
            let Some(sum) = self.summary.as_ref() else {
                debug_assert!(false);
                return false;
            };
            match sum.max() {
                None => {
                    self.max = self.min;
                }
                Some(last) => {
                    let li = last as usize;
                    if li >= self.clusters.len() {
                        debug_assert!(false);
                        return false;
                    }
                    let Some(cluster) = self.clusters[li].as_ref() else {
                        debug_assert!(false);
                        return false;
                    };
                    let Some(inner) = cluster.max() else {
                        debug_assert!(false);
                        return false;
                    };
                    self.max = Some(index(li, inner as usize, self.sq));
                }
            }
        }
        true
    }
}

/// Ordered queue with one FIFO per quantized key.
/// The tree tracks live keys. The map holds the per key queues in
/// arrival order. The pid index finds the key for direct removal.
pub struct FlowVeb {
    tree: Veb,
    queues: HashMap<u16, VecDeque<FlowEntry>>,
    pid_key: HashMap<u32, u16>,
    len: usize,
}

impl FlowVeb {
    /// Empty ordered queue over the full universe.
    pub fn new() -> Self {
        Self {
            tree: Veb::new(VEB_U),
            queues: HashMap::new(),
            pid_key: HashMap::new(),
            len: 0,
        }
    }

    /// Count of queued entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True when the queue holds zero entries.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True when the pid is queued.
    #[cfg(test)]
    pub fn contains_pid(&self, pid: u32) -> bool {
        self.pid_key.contains_key(&pid)
    }

    /// Insert one task by deadline. Duplicate pids join the fresh key.
    /// A duplicate holding the same key stays in place with the old
    /// deadline plus sequence, matching the core early return. A
    /// duplicate with a fresh key drops the old position and joins
    /// the tail of the fresh key. Zero identifiers pass through with
    /// no state change.
    pub fn insert(&mut self, pid: u32, deadline: u64, seq: u64) {
        if pid == 0 {
            return;
        }
        let key = quantize(deadline);
        if let Some(&old) = self.pid_key.get(&pid) {
            if old == key {
                return;
            }
            self.remove(pid);
        }
        let entry = FlowEntry { pid, deadline, seq };
        match self.queues.get_mut(&key) {
            Some(q) => {
                q.push_back(entry);
            }
            None => {
                let mut q = VecDeque::new();
                q.push_back(entry);
                self.queues.insert(key, q);
                self.tree.insert(key);
            }
        }
        self.pid_key.insert(pid, key);
        self.len += 1;
    }

    /// Least entry held with empty for vacant queues.
    #[cfg(test)]
    pub fn peek_min(&self) -> Option<&FlowEntry> {
        let k = self.tree.min()?;
        self.queues.get(&k)?.front()
    }

    /// Entries in dispatch order without removal.
    /// Least key wins and equal keys leave in insert order.
    /// Collects every queue then sorts by key plus sequence so the
    /// view matches repeated least removal.
    #[cfg(test)]
    pub fn ordered(&self) -> Vec<FlowEntry> {
        let mut out = Vec::with_capacity(self.len);
        for q in self.queues.values() {
            for e in q {
                out.push(e.clone());
            }
        }
        out.sort_by(|a, b| {
            quantize(a.deadline)
                .cmp(&quantize(b.deadline))
                .then(a.seq.cmp(&b.seq))
        });
        out
    }

    /// Remove and return the least entry.
    /// Least key wins and equal keys leave in insert order.
    #[cfg(test)]
    pub fn pop_min(&mut self) -> Option<FlowEntry> {
        let k = self.tree.min()?;
        let (entry, empty) = {
            let q = self.queues.get_mut(&k)?;
            let e = q.pop_front()?;
            (e, q.is_empty())
        };
        if empty {
            self.queues.remove(&k);
            self.tree.remove(k);
        }
        self.pid_key.remove(&entry.pid);
        self.len -= 1;
        Some(entry)
    }

    /// Remove one pid wherever it waits.
    /// Returns true when the pid was queued.
    /// Scan stays within one key queue. Total entries stay within the
    /// daemon depth bound of five hundred twelve, so a deeper bound
    /// needs a position index. The pid index finds the key directly
    /// and the queue position verifies the value so a reused pid never
    /// drops a fresh key. Empty keys clear the tree bit at once so no
    /// phantom key lingers. Zero identifiers pass through as missing.
    pub fn remove(&mut self, pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        let key = match self.pid_key.get(&pid).copied() {
            Some(k) => k,
            None => return false,
        };
        let empty = {
            let q = match self.queues.get_mut(&key) {
                Some(q) => q,
                None => {
                    self.pid_key.remove(&pid);
                    if self.len > 0 {
                        self.len -= 1;
                    }
                    self.tree.remove(key);
                    return false;
                }
            };
            let pos = q.iter().position(|e| e.pid == pid);
            match pos {
                Some(i) => {
                    q.remove(i);
                }
                None => return false,
            }
            q.is_empty()
        };
        if empty {
            self.queues.remove(&key);
            self.tree.remove(key);
        }
        self.pid_key.remove(&pid);
        self.len -= 1;
        true
    }

    /// Remove one pid solely when it still holds the expected key.
    /// Mirrors the BPF keyed drop on move. Stale expects pass through
    /// with no state change so a reused pid never drops a fresh key.
    /// Zero identifiers pass through as missing.
    #[cfg(test)]
    pub fn remove_if_key(&mut self, pid: u32, expect: u16) -> bool {
        if pid == 0 {
            return false;
        }
        match self.pid_key.get(&pid).copied() {
            Some(k) if k == expect => self.remove(pid),
            _ => false,
        }
    }
}

impl Default for FlowVeb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn xorshift(mut s: u64) -> impl FnMut() -> u64 {
        move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        }
    }

    #[test]
    fn quantize_grows_and_saturates() {
        assert_eq!(quantize(0), 0);
        assert!(quantize(2_000_000) > quantize(1_000_000));
        assert_eq!(quantize(u64::MAX), 65535);
        assert_eq!(VEB_U, 65536);
    }

    #[test]
    fn empty_queue_behaves() {
        let mut q = FlowVeb::new();
        assert!(q.is_empty());
        assert_eq!(q.len(), 0);
        assert_eq!(q.peek_min(), None);
        assert_eq!(q.pop_min(), None);
        assert!(!q.remove(1));
    }

    #[test]
    fn single_key_keeps_fifo() {
        let mut q = FlowVeb::new();
        q.insert(1, 16_000_000, 1);
        q.insert(2, 16_000_000, 2);
        q.insert(3, 16_000_000, 3);
        assert_eq!(q.len(), 3);
        assert_eq!(q.pop_min().unwrap().pid, 1);
        assert_eq!(q.pop_min().unwrap().pid, 2);
        assert_eq!(q.pop_min().unwrap().pid, 3);
        assert!(q.is_empty());
    }

    #[test]
    fn least_deadline_wins() {
        let mut q = FlowVeb::new();
        q.insert(1, 32_000_000, 1);
        q.insert(2, 8_000_000, 2);
        q.insert(3, 16_000_000, 3);
        assert_eq!(q.peek_min().unwrap().pid, 2);
        assert_eq!(q.pop_min().unwrap().pid, 2);
        assert_eq!(q.pop_min().unwrap().pid, 3);
        assert_eq!(q.pop_min().unwrap().pid, 1);
    }

    #[test]
    fn direct_remove_keeps_order() {
        let mut q = FlowVeb::new();
        q.insert(1, 8_000_000, 1);
        q.insert(2, 16_000_000, 2);
        q.insert(3, 32_000_000, 3);
        assert!(q.remove(2));
        assert!(!q.contains_pid(2));
        assert_eq!(q.pop_min().unwrap().pid, 1);
        assert_eq!(q.pop_min().unwrap().pid, 3);
    }

    #[test]
    fn tree_height_stays_doubly_logarithmic() {
        let t = Veb::new(VEB_U);
        assert!(t.height() <= 5);
        let mut q = FlowVeb::new();
        for i in 0..200u32 {
            q.insert(i + 1, (i as u64 + 1) * 1_000_000, i as u64);
        }
        assert_eq!(q.len(), 200);
    }

    #[test]
    fn oracle_matches_sorted_order() {
        let mut q = FlowVeb::new();
        let mut oracle: BTreeMap<u16, VecDeque<FlowEntry>> = BTreeMap::new();
        let mut rng = xorshift(0x9E3779B97F4A7C15);
        for (seq, i) in (0..2000u32).enumerate() {
            let seq = seq as u64;
            let pid = 1000 + i;
            let deadline = (rng() % 64_000_000) + 1_000_000;
            let key = quantize(deadline);
            q.insert(pid, deadline, seq);
            oracle
                .entry(key)
                .or_default()
                .push_back(FlowEntry { pid, deadline, seq });
            if i % 7 == 0 {
                let a = q.pop_min().unwrap();
                let (_, oq) = oracle.iter_mut().next().unwrap();
                let b = oq.pop_front().unwrap();
                if oq.is_empty() {
                    let k = b.deadline >> QUANT_SHIFT;
                    let kk = (k.min(VEB_MASK)) as u16;
                    oracle.remove(&kk);
                }
                assert_eq!(a.pid, b.pid);
                assert_eq!(a.seq, b.seq);
            }
        }
        while let Some(a) = q.pop_min() {
            let (_, oq) = oracle.iter_mut().next().unwrap();
            let b = oq.pop_front().unwrap();
            if oq.is_empty() {
                let k = b.deadline >> QUANT_SHIFT;
                let kk = (k.min(VEB_MASK)) as u16;
                oracle.remove(&kk);
            }
            assert_eq!(a.pid, b.pid);
        }
        assert!(oracle.is_empty());
    }

    #[test]
    fn oracle_matches_arbitrary_removal() {
        let mut q = FlowVeb::new();
        for i in 0..500u32 {
            q.insert(i + 1, ((i as u64 % 32) + 1) * 2_000_000, i as u64);
        }
        for pid in (1..=500u32).step_by(3) {
            assert!(q.remove(pid));
        }
        assert_eq!(q.len(), 500 - 167);
        let mut last_key = 0u16;
        let mut first = true;
        while let Some(e) = q.pop_min() {
            let k = quantize(e.deadline);
            if !first {
                assert!(k >= last_key);
            }
            first = false;
            last_key = k;
        }
    }

    #[test]
    fn ordered_view_matches_pop_sequence() {
        let mut q = FlowVeb::new();
        q.insert(1, 32_000_000, 1);
        q.insert(2, 8_000_000, 2);
        q.insert(3, 16_000_000, 3);
        q.insert(4, 16_000_000, 4);
        let view: Vec<u32> = q.ordered().iter().map(|e| e.pid).collect();
        assert_eq!(view, vec![2, 3, 4, 1]);
        let mut popped = Vec::new();
        while let Some(e) = q.pop_min() {
            popped.push(e.pid);
        }
        assert_eq!(popped, view);
    }

    #[test]
    fn zero_identifier_stays_out() {
        let mut q = FlowVeb::new();
        q.insert(0, 8_000_000, 1);
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
        assert!(!q.remove(0));
        q.insert(1, 8_000_000, 1);
        assert_eq!(q.len(), 1);
        assert!(!q.remove(0));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn empty_key_clears_tree_bit() {
        let mut q = FlowVeb::new();
        q.insert(1, 8_000_000, 1);
        assert_eq!(q.peek_min().unwrap().pid, 1);
        assert!(q.remove(1));
        assert!(q.is_empty());
        assert_eq!(q.peek_min(), None);
        assert_eq!(q.pop_min(), None);
        q.insert(2, 8_000_000, 2);
        assert_eq!(q.peek_min().unwrap().pid, 2);
    }

    #[test]
    fn remove_verifies_queue_position() {
        let mut q = FlowVeb::new();
        q.insert(1, 8_000_000, 1);
        q.insert(2, 16_000_000, 2);
        assert!(!q.remove(99));
        assert_eq!(q.len(), 2);
        assert!(q.remove(1));
        assert!(!q.contains_pid(1));
        assert!(q.contains_pid(2));
        assert!(!q.remove(1));
        assert_eq!(q.len(), 1);
    }

    /// Flat bitmap mirror of the BPF tree plus ledger for coverage.
    /// Replicates quantize, high, low, insert, remove, keyed remove,
    /// cached plus scan least plus greatest order exactly as the tree
    /// behaves single threaded, with successor kept as a tree query
    /// for tests. Admission plus order rows land
    /// synchronously in the core with the mirror kept as oracle for
    /// tests plus observability solely. Compare and swap loops
    /// collapse to one update here while contention fallbacks stay
    /// park counted in the BPF code. Within key order stays out since
    /// the core keeps park order in the overflow tail, not in the
    /// tree.
    struct BpfMirror {
        summary: [u64; 4],
        clusters: [u64; 1024],
        counts: Vec<u32>,
        pid: HashMap<u32, u16>,
        root_min: Option<u16>,
        root_max: Option<u16>,
        parks: u64,
    }

    /// Cap of the BPF pid rows mirroring the map bound.
    const MIRROR_PID_CAP: usize = 4096;

    impl BpfMirror {
        fn new() -> Self {
            Self {
                summary: [0; 4],
                clusters: [0; 1024],
                counts: vec![0; VEB_U],
                pid: HashMap::new(),
                root_min: None,
                root_max: None,
                parks: 0,
            }
        }

        fn len(&self) -> usize {
            self.pid.len()
        }

        fn quant(deadline: u64) -> u16 {
            (deadline >> QUANT_SHIFT).min(VEB_MASK) as u16
        }

        fn high(k: u16) -> usize {
            (k as usize) >> 8
        }

        fn low(k: u16) -> usize {
            (k as usize) & 255
        }

        fn set_bit(&mut self, k: u16) {
            let h = Self::high(k);
            let l = Self::low(k);
            self.clusters[h * 4 + (l >> 6)] |= 1u64 << (l & 63);
            self.summary[h >> 6] |= 1u64 << (h & 63);
        }

        fn root_insert(&mut self, k: u16) {
            match (self.root_min, self.root_max) {
                (None, _) => {
                    self.root_min = Some(k);
                    self.root_max = Some(k);
                }
                _ => {
                    if Some(k) < self.root_min {
                        self.root_min = Some(k);
                    }
                    if Some(k) > self.root_max {
                        self.root_max = Some(k);
                    }
                }
            }
        }

        fn cluster_first(&self, h: usize) -> Option<usize> {
            for w in 0..4 {
                let v = self.clusters[h * 4 + w];
                if v == 0 {
                    continue;
                }
                let b = v.trailing_zeros() as usize;
                if b >= 64 {
                    continue;
                }
                return Some(w * 64 + b);
            }
            None
        }

        fn cluster_last(&self, h: usize) -> Option<usize> {
            let mut best: Option<usize> = None;
            for w in 0..4 {
                let v = self.clusters[h * 4 + w];
                if v == 0 {
                    continue;
                }
                if v.leading_zeros() >= 64 {
                    continue;
                }
                let top = 63 - v.leading_zeros() as usize;
                best = Some(w * 64 + top);
            }
            best
        }

        fn scan_min(&self) -> Option<u16> {
            for w in 0..4 {
                let v = self.summary[w];
                if v == 0 {
                    continue;
                }
                let b = v.trailing_zeros() as usize;
                if b >= 64 {
                    continue;
                }
                let h = w * 64 + b;
                debug_assert!(h < 256);
                if let Some(l) = self.cluster_first(h) {
                    return Some((h * 256 + l) as u16);
                }
            }
            None
        }

        fn scan_max(&self) -> Option<u16> {
            for w in 0..4 {
                let r = 3 - w;
                let v = self.summary[r];
                if v == 0 {
                    continue;
                }
                if v.leading_zeros() >= 64 {
                    continue;
                }
                let b = 63 - v.leading_zeros() as usize;
                let h = r * 64 + b;
                debug_assert!(h < 256);
                if let Some(l) = self.cluster_last(h) {
                    return Some((h * 256 + l) as u16);
                }
            }
            None
        }

        fn min(&self) -> Option<u16> {
            match (self.root_min, self.scan_min()) {
                (None, s) => s,
                (c, None) => c,
                (Some(c), Some(s)) => Some(c.min(s)),
            }
        }

        fn succ(&self, x: u16) -> Option<u16> {
            if x == u16::MAX {
                return None;
            }
            let h = Self::high(x);
            let l = Self::low(x);
            let hw = l >> 6;
            let hb = l & 63;
            let v = self.clusters[h * 4 + hw];
            let mask = if hb >= 63 { 0 } else { u64::MAX << (hb + 1) };
            if v & mask != 0 {
                let b = (v & mask).trailing_zeros() as usize;
                if b < 64 {
                    return Some((h * 256 + hw * 64 + b) as u16);
                }
            }
            for w in 0..4 {
                let cand = hw as i32 + 1 + w;
                if !(0..4).contains(&cand) {
                    continue;
                }
                let v = self.clusters[h * 4 + cand as usize];
                if v == 0 {
                    continue;
                }
                let b = v.trailing_zeros() as usize;
                if b >= 64 {
                    continue;
                }
                return Some((h * 256 + cand as usize * 64 + b) as u16);
            }
            let sh = h >> 6;
            let sb = h & 63;
            let v = self.summary[sh];
            let mask = if sb >= 63 { 0 } else { u64::MAX << (sb + 1) };
            if v & mask != 0 {
                let b = (v & mask).trailing_zeros() as usize;
                if b < 64 {
                    let h2 = sh * 64 + b;
                    debug_assert!(h2 < 256);
                    if let Some(l2) = self.cluster_first(h2) {
                        return Some((h2 * 256 + l2) as u16);
                    }
                }
            }
            for w in 0..4 {
                let cand = sh as i32 + 1 + w;
                if !(0..4).contains(&cand) {
                    continue;
                }
                let sv = self.summary[cand as usize];
                if sv == 0 {
                    continue;
                }
                let sb2 = sv.trailing_zeros() as usize;
                if sb2 >= 64 {
                    continue;
                }
                let h2 = cand as usize * 64 + sb2;
                debug_assert!(h2 < 256);
                if let Some(l2) = self.cluster_first(h2) {
                    return Some((h2 * 256 + l2) as u16);
                }
            }
            None
        }

        fn clear_bit(&mut self, k: u16) {
            let h = Self::high(k);
            let l = Self::low(k);
            self.clusters[h * 4 + (l >> 6)] &= !(1u64 << (l & 63));
            if (0..4).all(|w| self.clusters[h * 4 + w] == 0) {
                self.summary[h >> 6] &= !(1u64 << (h & 63));
            }
        }

        fn root_remove(&mut self, k: u16) {
            if Some(k) != self.root_min && Some(k) != self.root_max {
                return;
            }
            if Some(k) == self.root_min {
                match self.scan_min() {
                    None => {
                        self.root_min = None;
                        self.root_max = None;
                    }
                    Some(nmn) => {
                        if self.root_min == Some(k) {
                            self.root_min = Some(nmn);
                        }
                    }
                }
            }
            if Some(k) == self.root_max {
                match self.scan_max() {
                    None => {
                        self.root_min = None;
                        self.root_max = None;
                    }
                    Some(nmx) => {
                        if self.root_max == Some(k) {
                            self.root_max = Some(nmx);
                        }
                    }
                }
            }
        }

        fn insert(&mut self, pid: u32, deadline: u64) {
            if pid == 0 {
                return;
            }
            let k = Self::quant(deadline);
            if let Some(&old) = self.pid.get(&pid) {
                if old == k {
                    return;
                }
                self.remove(pid);
            }
            let ki = k as usize;
            if self.counts[ki] == u32::MAX {
                self.parks += 1;
                return;
            }
            let prev = self.counts[ki];
            if !self.pid.contains_key(&pid) && self.pid.len() >= MIRROR_PID_CAP {
                self.parks += 1;
                return;
            }
            self.counts[ki] = prev + 1;
            self.pid.insert(pid, k);
            self.set_bit(k);
            if prev == 0 {
                self.root_insert(k);
            }
        }

        fn remove(&mut self, pid: u32) -> bool {
            if pid == 0 {
                return false;
            }
            let k = match self.pid.get(&pid).copied() {
                Some(k) => k,
                None => return false,
            };
            let ki = k as usize;
            if self.counts[ki] == 0 {
                self.pid.remove(&pid);
                self.clear_bit(k);
                self.root_remove(k);
                return true;
            }
            let prev = self.counts[ki];
            self.counts[ki] = prev - 1;
            self.pid.remove(&pid);
            if prev != 1 {
                return true;
            }
            self.clear_bit(k);
            self.root_remove(k);
            true
        }

        fn remove_if_key(&mut self, pid: u32, expect: u16) -> bool {
            if pid == 0 {
                return false;
            }
            match self.pid.get(&pid).copied() {
                Some(k) if k == expect => self.remove(pid),
                _ => false,
            }
        }

        fn succ_chain(&self) -> Vec<u16> {
            let mut out = Vec::new();
            let mut cur = self.min();
            while let Some(k) = cur {
                out.push(k);
                cur = self.succ(k);
            }
            out
        }
    }

    /// Dispatch loop model mirroring the tree order shape.
    /// Starts from the least key, follows successors, caps key probes,
    /// stops at the batch bound, skips empty keys through counts, picks
    /// one pid per visited key. Returns moved plus probes spent.
    fn dispatch_model(m: &mut BpfMirror, cap: usize, batch: usize) -> (usize, usize) {
        let mut moved = 0;
        let mut probes = 0;
        let mut cur = m.min();
        for _ in 0..cap {
            if moved >= batch {
                break;
            }
            let k = match cur {
                Some(k) => k,
                None => break,
            };
            probes += 1;
            if m.counts[k as usize] == 0 {
                cur = m.succ(k);
                continue;
            }
            let pid = match m.pid.iter().find(|kv| *kv.1 == k).map(|(&p, _)| p) {
                Some(p) => p,
                None => {
                    cur = m.succ(k);
                    continue;
                }
            };
            m.remove(pid);
            moved += 1;
            if m.counts[k as usize] == 0 {
                cur = m.succ(k);
            }
        }
        (moved, probes)
    }

    fn ordered_keys(q: &FlowVeb) -> Vec<u16> {
        let mut keys: Vec<u16> = Vec::new();
        for e in q.ordered() {
            let k = quantize(e.deadline);
            if keys.last() != Some(&k) {
                keys.push(k);
            }
        }
        keys
    }

    #[test]
    fn bpf_mirror_matches_flow_veb_on_random_ops() {
        let mut q = FlowVeb::new();
        let mut m = BpfMirror::new();
        let mut rng = xorshift(0x2545F4914F6CDD1D);
        for i in 0..1500u32 {
            let pid = 5000 + i;
            let deadline = (rng() % 64_000_000) + 1_000;
            q.insert(pid, deadline, i as u64);
            m.insert(pid, deadline);
            assert_eq!(q.len(), m.len());
        }
        assert_eq!(ordered_keys(&q), m.succ_chain());
        assert_eq!(q.peek_min().map(|e| quantize(e.deadline)), m.min());
        for pid in (5000..6500u32).step_by(7) {
            assert!(q.remove(pid));
            assert!(m.remove(pid));
        }
        assert_eq!(q.len(), m.len());
        assert_eq!(ordered_keys(&q), m.succ_chain());
        assert_eq!(q.peek_min().map(|e| quantize(e.deadline)), m.min());
        while let Some(e) = q.pop_min() {
            let k = quantize(e.deadline);
            assert_eq!(m.min(), Some(k));
            assert!(m.remove(e.pid));
        }
        assert_eq!(m.len(), 0);
        assert_eq!(m.min(), None);
        assert_eq!(m.succ_chain(), Vec::<u16>::new());
    }

    #[test]
    fn bpf_mirror_covers_saturation_empty_duplicate_successor_edges() {
        let mut m = BpfMirror::new();
        assert_eq!(m.min(), None);
        assert_eq!(m.succ(0), None);
        assert!(!m.remove(42));
        assert!(!m.remove_if_key(42, 0));
        assert_eq!(BpfMirror::quant(u64::MAX), 65535);
        m.insert(1, u64::MAX);
        assert_eq!(m.min(), Some(65535));
        assert_eq!(m.succ(65535), None);
        m.insert(1, u64::MAX);
        assert_eq!(m.len(), 1);
        let mut m2 = BpfMirror::new();
        m2.insert(10, 255u64 << QUANT_SHIFT);
        m2.insert(11, 256u64 << QUANT_SHIFT);
        assert_eq!(m2.min(), Some(255));
        assert_eq!(m2.succ(0), Some(255));
        assert_eq!(m2.succ(254), Some(255));
        assert_eq!(m2.succ(255), Some(256));
        assert_eq!(m2.succ(256), None);
        m2.insert(10, 256u64 << QUANT_SHIFT);
        assert_eq!(m2.min(), Some(256));
        assert_eq!(m2.len(), 2);
        assert!(!m2.remove_if_key(10, 255));
        assert_eq!(m2.len(), 2);
        assert!(m2.remove_if_key(10, 256));
        assert_eq!(m2.len(), 1);
        m2.insert(0, 1000);
        assert_eq!(m2.len(), 1);
        assert!(!m2.remove(0));
        assert!(!m2.remove_if_key(0, 0));
    }

    #[test]
    fn full_pid_map_rolls_back_count_with_one_park() {
        let mut m = BpfMirror::new();
        for pid in 1..=MIRROR_PID_CAP as u32 {
            m.insert(pid, ((pid as u64 % 32) + 1) << QUANT_SHIFT);
        }
        assert_eq!(m.len(), MIRROR_PID_CAP);
        let key = BpfMirror::quant(1u64 << QUANT_SHIFT);
        let before = m.counts[key as usize];
        m.insert(MIRROR_PID_CAP as u32 + 1, 1u64 << QUANT_SHIFT);
        assert_eq!(m.parks, 1);
        assert_eq!(m.len(), MIRROR_PID_CAP);
        assert_eq!(m.counts[key as usize], before);
        assert_eq!(m.min(), m.scan_min());
    }

    #[test]
    fn dispatch_probes_stay_capped_with_batch_bound() {
        const PROBES: usize = crate::flow::DISPATCH_PROBES;
        const BATCH: usize = crate::flow::DISPATCH_BATCH;
        let mut dense = BpfMirror::new();
        for i in 0..40u32 {
            dense.insert(100 + i, (i as u64) << QUANT_SHIFT);
        }
        let (moved, probes) = dispatch_model(&mut dense, PROBES, BATCH);
        assert_eq!(moved, BATCH);
        assert_eq!(probes, BATCH);
        assert_eq!(dense.len(), 40 - BATCH);
        let mut sparse = BpfMirror::new();
        for i in 0..16u32 {
            sparse.insert(200 + i, (i as u64 * 1000) << QUANT_SHIFT);
        }
        let (moved, probes) = dispatch_model(&mut sparse, PROBES, BATCH);
        assert_eq!(moved, BATCH);
        assert!(probes <= PROBES);
        assert_eq!(sparse.len(), 0);
        let mut stale = BpfMirror::new();
        for i in 0..10u32 {
            stale.insert(300 + i, (i as u64) << QUANT_SHIFT);
        }
        for k in [2u16, 4, 6, 8, 10] {
            stale.counts[k as usize] = 0;
        }
        let (moved, probes) = dispatch_model(&mut stale, PROBES, BATCH);
        assert_eq!(moved, 6);
        assert!(probes <= PROBES);
        assert!(probes > moved);
        let mut empty = BpfMirror::new();
        let (moved, probes) = dispatch_model(&mut empty, PROBES, BATCH);
        assert_eq!((moved, probes), (0, 0));
    }

    #[test]
    fn rapid_requeue_keeps_fresh_key() {
        let mut q = FlowVeb::new();
        q.insert(7, 8_000_000, 1);
        let stale = quantize(8_000_000);
        assert!(q.remove(7));
        q.insert(7, 32_000_000, 2);
        let fresh = quantize(32_000_000);
        assert_ne!(stale, fresh);
        assert!(!q.remove_if_key(7, stale));
        assert!(q.contains_pid(7));
        assert_eq!(q.peek_min().unwrap().pid, 7);
        assert!(q.remove_if_key(7, fresh));
        assert!(q.is_empty());
        assert!(!q.remove_if_key(7, fresh));
        assert!(!q.remove_if_key(0, fresh));
    }

    #[test]
    fn same_key_duplicate_stays_in_place() {
        let mut q = FlowVeb::new();
        q.insert(7, 8_000_000, 1);
        assert_eq!(quantize(8_000_500), quantize(8_000_000));
        q.insert(7, 8_000_500, 2);
        assert_eq!(q.len(), 1);
        assert_eq!(q.peek_min().unwrap().deadline, 8_000_000);
        assert_eq!(q.peek_min().unwrap().seq, 1);
        let mut m = BpfMirror::new();
        m.insert(7, 8_000_000);
        m.insert(7, 8_000_500);
        assert_eq!(m.len(), 1);
        assert_eq!(q.peek_min().map(|e| quantize(e.deadline)), m.min());
        q.insert(7, 32_000_000, 3);
        assert_eq!(q.len(), 1);
        assert_eq!(q.peek_min().unwrap().seq, 3);
        m.insert(7, 32_000_000);
        assert_eq!(m.len(), 1);
        assert_eq!(q.peek_min().map(|e| quantize(e.deadline)), m.min());
    }

    #[test]
    fn high_stays_within_256_after_saturate() {
        for d in [0u64, 1, 1023, 1024, 1_000_000, 67_000_000, u64::MAX] {
            let k = quantize(d);
            assert!((k as usize) < VEB_U);
            assert!((k >> 8) < 256);
        }
        assert_eq!(quantize(u64::MAX), 65535);
        assert_eq!(65535u16 >> 8, 255);
        let mut m = BpfMirror::new();
        m.insert(1, u64::MAX);
        assert_eq!(BpfMirror::high(65535), 255);
        assert_eq!(m.min(), Some(65535));
    }

    #[test]
    fn cas_fallback_parks_then_retry_heals_bit() {
        let mut m = BpfMirror::new();
        let k = BpfMirror::quant(8_000_000);
        m.insert(1, 8_000_000);
        m.counts[k as usize] = u32::MAX;
        m.insert(2, 8_000_000);
        assert_eq!(m.parks, 1);
        assert_eq!(m.len(), 1);
        let mut n = BpfMirror::new();
        n.insert(3, 8_000_000);
        let h = BpfMirror::high(k);
        let l = BpfMirror::low(k);
        n.clusters[h * 4 + (l >> 6)] = 0;
        n.summary[h >> 6] = 0;
        n.insert(4, 8_000_000);
        assert_eq!(n.min(), Some(k));
        assert_eq!(n.len(), 2);
        let mut z = BpfMirror::new();
        z.insert(5, 8_000_000);
        z.counts[k as usize] = 0;
        assert!(z.remove(5));
        assert_eq!(z.min(), None);
        assert_eq!(z.succ_chain(), Vec::<u16>::new());
    }
}
