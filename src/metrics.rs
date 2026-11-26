use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct RelayMetrics {
    pub requests_total: AtomicU64,
    pub mode_pass_total: AtomicU64,
    pub mode_full_total: AtomicU64,
    pub mode_delta_total: AtomicU64,
    pub miss_retries_total: AtomicU64,
    pub errors_total: AtomicU64,
    pub raw_bytes_total: AtomicU64,
    pub wire_bytes_total: AtomicU64,
}

#[derive(Debug, Serialize)]
pub struct StatsSnapshot {
    pub role: &'static str,
    pub requests_total: u64,
    pub mode_pass_total: u64,
    pub mode_full_total: u64,
    pub mode_delta_total: u64,
    pub miss_retries_total: u64,
    pub errors_total: u64,
    pub raw_bytes_total: u64,
    pub wire_bytes_total: u64,
    pub saved_bytes_total: u64,
    pub savings_percent: f64,
    pub lru_entries: usize,
    pub lru_bytes: usize,
    pub lru_max_bytes: usize,
    pub lru_evictions_total: u64,
}

impl RelayMetrics {
    pub fn snapshot(
        &self,
        role: &'static str,
        lru_entries: usize,
        lru_bytes: usize,
        lru_max_bytes: usize,
        lru_evictions_total: u64,
    ) -> StatsSnapshot {
        let raw = self.raw_bytes_total.load(Ordering::Relaxed);
        let wire = self.wire_bytes_total.load(Ordering::Relaxed);
        let saved = raw.saturating_sub(wire);
        let savings_percent = if raw > 0 {
            ((saved as f64) / (raw as f64)) * 100.0
        } else {
            0.0
        };
        StatsSnapshot {
            role,
            requests_total: self.requests_total.load(Ordering::Relaxed),
            mode_pass_total: self.mode_pass_total.load(Ordering::Relaxed),
            mode_full_total: self.mode_full_total.load(Ordering::Relaxed),
            mode_delta_total: self.mode_delta_total.load(Ordering::Relaxed),
            miss_retries_total: self.miss_retries_total.load(Ordering::Relaxed),
            errors_total: self.errors_total.load(Ordering::Relaxed),
            raw_bytes_total: raw,
            wire_bytes_total: wire,
            saved_bytes_total: saved,
            savings_percent: (savings_percent * 100.0).round() / 100.0,
            lru_entries,
            lru_bytes,
            lru_max_bytes,
            lru_evictions_total,
        }
    }
}
