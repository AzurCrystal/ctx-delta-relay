use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Conservative per-entry bookkeeping overhead (HashMap slot + Arc header + VecDeque entry).
const ENTRY_OVERHEAD_BYTES: usize = 160;

/// O(1)-amortized byte-bounded TTL LRU cache storing exact-sized `Arc<[u8]>` zstd snapshots.
/// Zero disk usage; strictly enforces `current_bytes <= max_bytes` with zero spare Vec capacity.
pub struct ByteBoundedLru {
    max_bytes: usize,
    ttl: Duration,
    current_bytes: usize,
    evictions: u64,
    next_seq: u64,
    entries: HashMap<[u8; 32], CacheEntry>,
    order: VecDeque<([u8; 32], u64)>,
}

struct CacheEntry {
    data: Arc<[u8]>,
    accounted_bytes: usize,
    expires_at: Instant,
    seq: u64,
}

impl ByteBoundedLru {
    pub fn new(max_bytes: usize, ttl: Duration) -> Self {
        Self {
            max_bytes,
            ttl,
            current_bytes: 0,
            evictions: 0,
            next_seq: 1,
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    pub fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    fn footprint(payload_len: usize) -> usize {
        payload_len.saturating_add(ENTRY_OVERHEAD_BYTES)
    }

    /// Look up a cached compressed snapshot by BLAKE3 key; refreshes LRU position and TTL.
    pub fn get(&mut self, key: &[u8; 32]) -> Option<Arc<[u8]>> {
        let now = Instant::now();
        let expired = now >= self.entries.get(key)?.expires_at;
        if expired {
            self.remove(key);
            return None;
        }
        let seq = self.alloc_seq();
        let entry = self.entries.get_mut(key)?;
        entry.seq = seq;
        entry.expires_at = now + self.ttl;
        let data = Arc::clone(&entry.data);
        self.order.push_back((*key, seq));
        self.compact_order_if_needed();
        Some(data)
    }

    /// Check existence without touching payload.
    pub fn contains_fresh(&mut self, key: &[u8; 32]) -> bool {
        let now = Instant::now();
        match self.entries.get(key) {
            Some(e) if now < e.expires_at => true,
            Some(_) => {
                self.remove(key);
                false
            }
            None => false,
        }
    }

    /// Insert or refresh an exact-sized compressed snapshot while strictly keeping `current_bytes <= max_bytes`.
    pub fn insert(&mut self, key: [u8; 32], data: Arc<[u8]>) -> bool {
        if data.is_empty() {
            return false;
        }
        let accounted = Self::footprint(data.len());
        if accounted > self.max_bytes {
            return false;
        }
        let now = Instant::now();
        self.purge_expired(now);

        if let Some(existing) = self.entries.remove(&key) {
            self.current_bytes = self.current_bytes.saturating_sub(existing.accounted_bytes);
        }

        while self.current_bytes + accounted > self.max_bytes {
            if !self.evict_oldest() {
                break;
            }
        }

        if self.current_bytes + accounted > self.max_bytes {
            return false;
        }

        let seq = self.alloc_seq();
        self.current_bytes += accounted;
        self.entries.insert(
            key,
            CacheEntry {
                data,
                accounted_bytes: accounted,
                expires_at: now + self.ttl,
                seq,
            },
        );
        self.order.push_back((key, seq));
        self.compact_order_if_needed();
        true
    }

    pub fn remove(&mut self, key: &[u8; 32]) -> bool {
        if let Some(old) = self.entries.remove(key) {
            self.current_bytes = self.current_bytes.saturating_sub(old.accounted_bytes);
            true
        } else {
            false
        }
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
        self.current_bytes = 0;
    }

    pub fn purge_expired(&mut self, now: Instant) -> usize {
        let mut removed = 0usize;
        while let Some(&(key, seq)) = self.order.front() {
            match self.entries.get(&key) {
                Some(entry) if entry.seq == seq => {
                    if now >= entry.expires_at {
                        self.order.pop_front();
                        if let Some(old) = self.entries.remove(&key) {
                            self.current_bytes =
                                self.current_bytes.saturating_sub(old.accounted_bytes);
                            removed += 1;
                        }
                    } else {
                        break;
                    }
                }
                _ => {
                    self.order.pop_front();
                }
            }
        }
        removed
    }

    fn evict_oldest(&mut self) -> bool {
        while let Some((key, seq)) = self.order.pop_front() {
            if let Some(entry) = self.entries.get(&key)
                && entry.seq == seq
                && let Some(old) = self.entries.remove(&key)
            {
                self.current_bytes = self.current_bytes.saturating_sub(old.accounted_bytes);
                self.evictions += 1;
                return true;
            }
        }
        false
    }

    fn alloc_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        seq
    }

    fn compact_order_if_needed(&mut self) {
        if self.order.len() > self.entries.len().saturating_mul(4).max(1024) {
            let entries = &self.entries;
            self.order.retain(|(k, seq)| {
                entries.get(k).map(|e| e.seq == *seq).unwrap_or(false)
            });
        }
    }
}

/// Sender-side lightweight index mapping a conversation fingerprint to up to 3 recent
/// snapshot records `(full_hash, raw_len, ts)` so retries and branched turns pick the best base.
pub struct SessionIndex {
    max_sessions: usize,
    ttl: Duration,
    sessions: HashMap<[u8; 32], SessionSlot>,
}

struct SessionSlot {
    recent: VecDeque<([u8; 32], usize, Instant)>,
    last_seen: Instant,
}

impl SessionIndex {
    pub fn new(max_sessions: usize, ttl: Duration) -> Self {
        Self {
            max_sessions,
            ttl,
            sessions: HashMap::new(),
        }
    }

    /// Return candidate base hashes ranked for `(curr_hash, curr_raw_len)`:
    /// 1. Exact `curr_hash` match (identical retry => near-0-byte delta).
    /// 2. Candidates with `raw_len <= curr_raw_len`, largest `raw_len` first (best growing prefix).
    /// 3. Remaining candidates sorted by smallest `|raw_len - curr_raw_len|`, newest tie-break.
    pub fn ranked_candidates(
        &mut self,
        session_key: &[u8; 32],
        curr_hash: &[u8; 32],
        curr_raw_len: usize,
    ) -> Vec<[u8; 32]> {
        let now = Instant::now();
        let Some(slot) = self.sessions.get_mut(session_key) else {
            return Vec::new();
        };
        slot.recent
            .retain(|(_, _, ts)| now.saturating_duration_since(*ts) < self.ttl);
        if slot.recent.is_empty() {
            self.sessions.remove(session_key);
            return Vec::new();
        }
        slot.last_seen = now;

        let mut items: Vec<(usize, [u8; 32], usize)> = slot
            .recent
            .iter()
            .enumerate()
            .map(|(idx, &(h, len, _))| (idx, h, len))
            .collect();

        items.sort_by(|&(idx_a, ha, la), &(idx_b, hb, lb)| {
            let exact_a = ha == *curr_hash;
            let exact_b = hb == *curr_hash;
            if exact_a != exact_b {
                return exact_b.cmp(&exact_a);
            }
            let le_a = la <= curr_raw_len;
            let le_b = lb <= curr_raw_len;
            if le_a != le_b {
                return le_b.cmp(&le_a);
            }
            let diff_a = curr_raw_len.abs_diff(la);
            let diff_b = curr_raw_len.abs_diff(lb);
            diff_a.cmp(&diff_b).then_with(|| idx_b.cmp(&idx_a))
        });

        items.into_iter().map(|(_, h, _)| h).collect()
    }

    /// Record that `full_hash` is confirmed cached on receiver for `session_key`.
    pub fn record(&mut self, session_key: [u8; 32], full_hash: [u8; 32], raw_len: usize) {
        let now = Instant::now();
        if self.sessions.len() >= self.max_sessions && !self.sessions.contains_key(&session_key) {
            self.evict_stale_or_oldest(now);
        }
        let slot = self.sessions.entry(session_key).or_insert_with(|| SessionSlot {
            recent: VecDeque::with_capacity(4),
            last_seen: now,
        });
        slot.last_seen = now;
        slot.recent.retain(|(h, _, _)| *h != full_hash);
        slot.recent.push_back((full_hash, raw_len, now));
        while slot.recent.len() > 3 {
            slot.recent.pop_front();
        }
    }

    /// Forget a hash across a session after a 409 Cache-Miss.
    pub fn invalidate_hash(&mut self, session_key: &[u8; 32], bad_hash: &[u8; 32]) {
        if let Some(slot) = self.sessions.get_mut(session_key) {
            slot.recent.retain(|(h, _, _)| h != bad_hash);
            if slot.recent.is_empty() {
                self.sessions.remove(session_key);
            }
        }
    }

    fn evict_stale_or_oldest(&mut self, now: Instant) {
        self.sessions
            .retain(|_, s| now.saturating_duration_since(s.last_seen) < self.ttl);
        if self.sessions.len() >= self.max_sessions
            && let Some((&oldest_key, _)) = self.sessions.iter().min_by_key(|(_, s)| s.last_seen)
        {
            self.sessions.remove(&oldest_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_enforces_hard_byte_cap_including_overhead() {
        let entry_cost = 100 + ENTRY_OVERHEAD_BYTES;
        let cap = entry_cost * 2 + 50;
        let mut cache = ByteBoundedLru::new(cap, Duration::from_secs(60));
        let k1 = *blake3::hash(b"1").as_bytes();
        let k2 = *blake3::hash(b"2").as_bytes();
        let k3 = *blake3::hash(b"3").as_bytes();

        assert!(cache.insert(k1, Arc::from(vec![1u8; 100].into_boxed_slice())));
        assert!(cache.insert(k2, Arc::from(vec![2u8; 100].into_boxed_slice())));
        assert_eq!(cache.current_bytes(), entry_cost * 2);

        // Touch k1 so k2 becomes the oldest.
        assert!(cache.get(&k1).is_some());

        // Inserting k3 must evict k2, keeping k1 and k3 within cap.
        assert!(cache.insert(k3, Arc::from(vec![3u8; 100].into_boxed_slice())));
        assert!(cache.current_bytes() <= cap);
        assert_eq!(cache.evictions(), 1);
        assert!(cache.get(&k1).is_some());
        assert!(cache.get(&k2).is_none());
        assert!(cache.get(&k3).is_some());
    }

    #[test]
    fn lru_expires_by_ttl() {
        let mut cache = ByteBoundedLru::new(4096, Duration::from_millis(20));
        let k1 = *blake3::hash(b"exp").as_bytes();
        assert!(cache.insert(k1, Arc::from(vec![7u8; 64].into_boxed_slice())));
        std::thread::sleep(Duration::from_millis(35));
        assert!(cache.get(&k1).is_none());
        assert_eq!(cache.current_bytes(), 0);
    }

    #[test]
    fn session_index_ranks_best_prefix_candidate() {
        let mut idx = SessionIndex::new(16, Duration::from_secs(60));
        let sk = *blake3::hash(b"sess").as_bytes();
        let h_small = *blake3::hash(b"turn1").as_bytes();
        let h_big = *blake3::hash(b"turn2-long").as_bytes();
        let h_cur = *blake3::hash(b"turn2-retry").as_bytes();

        idx.record(sk, h_small, 100_000);
        idx.record(sk, h_big, 500_000);

        // New request of length 105_000 should pick h_small (<= 105_000), not h_big (500_000).
        let ranked = idx.ranked_candidates(&sk, &h_cur, 105_000);
        assert_eq!(ranked[0], h_small);

        // Exact retry of h_big should pick h_big first.
        let ranked_exact = idx.ranked_candidates(&sk, &h_big, 500_000);
        assert_eq!(ranked_exact[0], h_big);
    }
}
