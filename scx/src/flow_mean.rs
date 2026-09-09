/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2026 Galih Tama <galpt@v.recipes>
 *
 * Mean and estimate helpers for the flow scheduler.
 * The functions mirror the BPF header so behavior
 * stays the same on both sides of the boundary.
 */

/* Lower bound of a per task estimate in nanos. */
pub const EST_MIN_NS: u64 = 1;
/* Upper bound of a per task estimate in nanos. */
pub const EST_MAX_NS: u64 = 1_000_000_000;
/* Seed of a per-CPU mean in nanos. */
pub const TQ_SEED_NS: u64 = 8_000_000;
/* Floor of a per-CPU mean in nanos. */
pub const TQ_MIN_NS: u64 = 500_000;
/* Ceiling of a per-CPU mean in nanos. */
pub const TQ_MAX_NS: u64 = 32_000_000;
/* Hint used for short estimates. */
#[cfg(test)]
pub const CPUPERF_SHORT: u32 = 1024;
/* Hint used for long estimates. */
#[cfg(test)]
pub const CPUPERF_LONG: u32 = 0;
/* Cap of one sample in mean accounting in nanos. */
#[cfg(test)]
pub const ACCT_MAX_NS: u64 = 32_000_000;
/* Fixed weight used for virtual time scaling. */
#[cfg(test)]
pub const WEIGHT: u64 = 1024;

/*
 * Clamp a per task estimate to the estimate range.
 * The floor keeps the value positive. The ceiling
 * keeps a single long run from shaping later choice.
 */
#[cfg(test)]
pub fn clamp_est(v: u64) -> u64 {
    v.clamp(EST_MIN_NS, EST_MAX_NS)
}

/*
 * Cap one sample for mean accounting. The deadline
 * keeps the full clamped estimate. The accounting
 * value keeps the tighter cap, so a single long run
 * never moves the mean by more than the cap.
 */
#[cfg(test)]
pub fn clamp_acct(v: u64) -> u64 {
    clamp_est(v).min(ACCT_MAX_NS)
}

/*
 * Clamp a per-CPU mean to the mean range. The floor
 * keeps short means usable. The ceiling keeps long
 * means bounded.
 */
#[cfg(test)]
pub fn clamp_tq(v: u64) -> u64 {
    v.clamp(TQ_MIN_NS, TQ_MAX_NS)
}

/*
 * Mean of one CPU from sum and count. An empty CPU
 * uses the seed. A populated CPU uses the quotient
 * clamped to the mean range.
 */
#[cfg(test)]
pub fn mean_tq(sum: u64, nr: u64) -> u64 {
    if nr == 0 {
        return TQ_SEED_NS;
    }
    clamp_tq(sum / nr)
}

/*
 * Hint for one estimate against the mean. Short
 * estimates ask for the high hint. Long estimates
 * restore the low hint. The choice uses only the
 * estimate and the mean.
 */
#[cfg(test)]
pub fn cpuperf_for_est(est: u64, tq: u64) -> u32 {
    if est <= tq {
        CPUPERF_SHORT
    } else {
        CPUPERF_LONG
    }
}

/*
 * Scale an estimate by weight for virtual time. The
 * fixed weight keeps the value unchanged while the
 * signature allows future weights with no call change.
 */
#[cfg(test)]
pub fn scale_by_weight(est: u64, weight: u32) -> u64 {
    if weight == 0 {
        return est;
    }
    if weight == 1024 {
        return est;
    }
    ((est as u128 * 1024) / weight as u128) as u64
}

/*
 * Per-CPU mean for tests. Holds the sum and the count
 * of unfinished work including the running task. The
 * mean is the quotient clamped to the mean range with
 * the seed for an empty CPU.
 */
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuMean {
    /* Sum of capped estimates of unfinished tasks. */
    pub sum: u64,
    /* Count of unfinished tasks with the running one. */
    pub nr: u64,
}

#[cfg(test)]
impl CpuMean {
    /*
     * Empty mean with no work. The mean reads as the
     * seed while empty.
     */
    pub fn empty() -> Self {
        Self { sum: 0, nr: 0 }
    }

    /*
     * Current mean. An empty CPU reads as the seed.
     * A populated CPU reads as the clamped quotient.
     */
    pub fn tq(&self) -> u64 {
        mean_tq(self.sum, self.nr)
    }

    /*
     * Join one task with a fresh estimate. A fresh
     * estimate reads as the current mean, so the join
     * leaves the mean unchanged.
     */
    pub fn join_fresh(&mut self) -> u64 {
        let est = self.tq();
        self.sum = self.sum.saturating_add(est);
        self.nr = self.nr.saturating_add(1);
        est
    }

    /*
     * Join one task with a known estimate. The deadline
     * keeps the full clamped estimate. The sum keeps
     * the capped value, so outliers never dominate
     * the mean.
     */
    pub fn join(&mut self, est: u64) -> u64 {
        let e = clamp_est(est);
        let a = clamp_acct(est);
        self.sum = self.sum.saturating_add(a);
        self.nr = self.nr.saturating_add(1);
        e
    }

    /*
     * Leave one task with its estimate. The sum uses
     * the capped value to match the join path. The sum
     * never wraps below zero. The count never wraps
     * below zero.
     */
    pub fn leave(&mut self, est: u64) {
        let a = clamp_acct(est);
        self.sum = self.sum.saturating_sub(a);
        self.nr = self.nr.saturating_sub(1);
    }

    /*
     * Replace one estimate with a new value. Used when
     * a runnable task refreshes its last burst. The
     * count stays fixed while the sum tracks the capped
     * change. Equal estimates skip at once with no sum
     * change. The deadline still uses full values.
     */
    pub fn replace(&mut self, old: u64, new: u64) {
        if !crate::flow_edf::should_replace(old, new) {
            return;
        }
        let o = clamp_acct(old);
        let n = clamp_acct(new);
        if o == n {
            return;
        }
        self.sum = self.sum.saturating_sub(o);
        self.sum = self.sum.saturating_add(n);
    }
}
