// SPDX-License-Identifier: GPL-2.0
//! Quantized order for the flow daemon.
//!
//! Copyright (c) 2026 Galih Tama <galpt@v.recipes>

//! Holds the quantized order used by the daemon. Deadlines quantize to
//! a small key. Each key holds one FIFO queue. The tree finds the least
//! key in doubly logarithmic time. Equal keys leave in insert order.

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
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True when the pid is queued.
    #[cfg(test)]
    pub fn contains_pid(&self, pid: u32) -> bool {
        self.pid_key.contains_key(&pid)
    }

    /// Insert one task by deadline. Duplicate pids refresh in place.
    /// Refresh drops the old position and joins the tail of the fresh key.
    pub fn insert(&mut self, pid: u32, deadline: u64, seq: u64) {
        if self.pid_key.contains_key(&pid) {
            self.remove(pid);
        }
        let key = quantize(deadline);
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
    /// needs a position index. The pid index finds the key directly.
    pub fn remove(&mut self, pid: u32) -> bool {
        let key = match self.pid_key.get(&pid).copied() {
            Some(k) => k,
            None => return false,
        };
        let empty = {
            let q = match self.queues.get_mut(&key) {
                Some(q) => q,
                None => return false,
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
}
