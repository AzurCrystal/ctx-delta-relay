use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Conservative per-entry metadata overhead (HashMap key+bucket + Node links + Arc header).
/// With the intrusive doubly-linked list there are ZERO tombstone queue entries (R2-10).
const ENTRY_OVERHEAD_BYTES: usize = 192;

/// True O(1) intrusive doubly-linked TTL LRU cache storing exact-sized `Arc<[u8]>` zstd snapshots.
/// - Zero disk usage
/// - Zero stale/tombstone queue growth (every live entry occupies exactly 1 map slot)
/// - Strictly enforces `current_bytes <= max_bytes` including per-entry metadata overhead
/// - Shrinks backing HashMap capacity when utilization drops after eviction/expiry bursts
pub struct ByteBoundedLru {
    max_bytes: usize,
    ttl: Duration,
    current_bytes: usize,
    evictions: u64,
    entries: HashMap<[u8; 32], LruNode>,
    /// Most-recently-used key (newest TTL).
    head: Option<[u8; 32]>,
    /// Least-recently-used key (oldest TTL, evicted/expired first).
    tail: Option<[u8; 32]>,
}

struct LruNode {
    data: Arc<[u8]>,
    accounted_bytes: usize,
    expires_at: Instant,
    prev: Option<[u8; 32]>,
    next: Option<[u8; 32]>,
}

impl ByteBoundedLru {
    pub fn new(max_bytes: usize, ttl: Duration) -> Self {
        Self {
            max_bytes,
            ttl,
            current_bytes: 0,
            evictions: 0,
            entries: HashMap::new(),
            head: None,
            tail: None,
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

    /// Look up a cached compressed snapshot by scoped key; refreshes MRU position and TTL in O(1).
    pub fn get(&mut self, key: &[u8; 32]) -> Option<Arc<[u8]>> {
        let now = Instant::now();
        let expired = now >= self.entries.get(key)?.expires_at;
        if expired {
            self.remove(key);
            return None;
        }
        self.move_to_head(*key);
        let node = self.entries.get_mut(key)?;
        node.expires_at = now + self.ttl;
        Some(Arc::clone(&node.data))
    }

    /// Insert or refresh an exact-sized compressed snapshot while strictly enforcing `current_bytes <= max_bytes`.
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

        if self.entries.contains_key(&key) {
            self.remove(&key);
        }

        while self.current_bytes + accounted > self.max_bytes {
            if !self.evict_tail() {
                break;
            }
        }

        if self.current_bytes + accounted > self.max_bytes {
            return false;
        }

        let old_head = self.head;
        if let Some(h) = old_head
            && let Some(head_node) = self.entries.get_mut(&h)
        {
            head_node.prev = Some(key);
        }
        self.entries.insert(
            key,
            LruNode {
                data,
                accounted_bytes: accounted,
                expires_at: now + self.ttl,
                prev: None,
                next: old_head,
            },
        );
        self.head = Some(key);
        if self.tail.is_none() {
            self.tail = Some(key);
        }
        self.current_bytes += accounted;
        true
    }

    pub fn remove(&mut self, key: &[u8; 32]) -> bool {
        let Some(node) = self.entries.remove(key) else {
            return false;
        };
        self.current_bytes = self.current_bytes.saturating_sub(node.accounted_bytes);

        match node.prev {
            Some(p) => {
                if let Some(prev_node) = self.entries.get_mut(&p) {
                    prev_node.next = node.next;
                }
            }
            None => self.head = node.next,
        }
        match node.next {
            Some(n) => {
                if let Some(next_node) = self.entries.get_mut(&n) {
                    next_node.prev = node.prev;
                }
            }
            None => self.tail = node.prev,
        }

        self.maybe_shrink_map();
        true
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.entries.shrink_to_fit();
        self.head = None;
        self.tail = None;
        self.current_bytes = 0;
    }

    /// Expire entries from the LRU tail (oldest TTL first) in O(expired).
    pub fn purge_expired(&mut self, now: Instant) -> usize {
        let mut removed = 0usize;
        while let Some(tail_key) = self.tail {
            let is_expired = self
                .entries
                .get(&tail_key)
                .map(|n| now >= n.expires_at)
                .unwrap_or(false);
            if is_expired {
                self.remove(&tail_key);
                removed += 1;
            } else {
                break;
            }
        }
        removed
    }

    fn evict_tail(&mut self) -> bool {
        let Some(tail_key) = self.tail else {
            return false;
        };
        if self.remove(&tail_key) {
            self.evictions += 1;
            true
        } else {
            false
        }
    }

    fn move_to_head(&mut self, key: [u8; 32]) {
        if self.head == Some(key) {
            return;
        }
        let Some((prev, next)) = self.entries.get(&key).map(|n| (n.prev, n.next)) else {
            return;
        };

        // Detach from current position.
        if let Some(p) = prev
            && let Some(prev_node) = self.entries.get_mut(&p)
        {
            prev_node.next = next;
        }
        match next {
            Some(n) => {
                if let Some(next_node) = self.entries.get_mut(&n) {
                    next_node.prev = prev;
                }
            }
            None => self.tail = prev,
        }

        // Attach at head.
        let old_head = self.head;
        if let Some(h) = old_head
            && let Some(head_node) = self.entries.get_mut(&h)
        {
            head_node.prev = Some(key);
        }
        if let Some(node) = self.entries.get_mut(&key) {
            node.prev = None;
            node.next = old_head;
        }
        self.head = Some(key);
        if self.tail.is_none() {
            self.tail = Some(key);
        }
    }

    fn maybe_shrink_map(&mut self) {
        if self.entries.capacity() > 256 && self.entries.capacity() > self.entries.len().saturating_mul(4) {
            self.entries.shrink_to_fit();
        }
    }
}

/// Sender-side bounded index mapping a tenant-isolated conversation fingerprint to up to 3 recent
/// confirmed snapshot records `(content_hash, raw_len, ts)`.
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
            max_sessions: max_sessions.max(16),
            ttl,
            sessions: HashMap::new(),
        }
    }

    /// Return candidate content hashes ranked for `(curr_hash, curr_raw_len)`:
    /// 1. Exact `curr_hash` match (identical retry => near-0-byte delta).
    /// 2. Candidates with `raw_len <= curr_raw_len`, largest `raw_len` first.
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

    pub fn invalidate_hash(&mut self, session_key: &[u8; 32], bad_hash: &[u8; 32]) {
        if let Some(slot) = self.sessions.get_mut(session_key) {
            slot.recent.retain(|(h, _, _)| h != bad_hash);
            if slot.recent.is_empty() {
                self.sessions.remove(session_key);
            }
        }
    }

    pub fn purge_expired(&mut self, now: Instant) -> usize {
        let before = self.sessions.len();
        self.sessions
            .retain(|_, s| now.saturating_duration_since(s.last_seen) < self.ttl);
        if self.sessions.capacity() > 256
            && self.sessions.capacity() > self.sessions.len().saturating_mul(4)
        {
            self.sessions.shrink_to_fit();
        }
        before.saturating_sub(self.sessions.len())
    }

    fn evict_stale_or_oldest(&mut self, now: Instant) {
        self.purge_expired(now);
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
    fn intrusive_lru_enforces_cap_order_and_zero_leaks() {
        let entry_cost = 100 + ENTRY_OVERHEAD_BYTES;
        let cap = entry_cost * 2 + 50;
        let mut cache = ByteBoundedLru::new(cap, Duration::from_secs(60));
        let k1 = *blake3::hash(b"1").as_bytes();
        let k2 = *blake3::hash(b"2").as_bytes();
        let k3 = *blake3::hash(b"3").as_bytes();

        assert!(cache.insert(k1, Arc::from(vec![1u8; 100].into_boxed_slice())));
        assert!(cache.insert(k2, Arc::from(vec![2u8; 100].into_boxed_slice())));
        assert_eq!(cache.current_bytes(), entry_cost * 2);

        // Touch k1 so k2 moves to tail (LRU).
        assert!(cache.get(&k1).is_some());
        assert_eq!(cache.head, Some(k1));
        assert_eq!(cache.tail, Some(k2));

        // Inserting k3 must evict k2, keeping k1 and k3 within cap.
        assert!(cache.insert(k3, Arc::from(vec![3u8; 100].into_boxed_slice())));
        assert!(cache.current_bytes() <= cap);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.evictions(), 1);
        assert!(cache.get(&k1).is_some());
        assert!(cache.get(&k2).is_none());
        assert!(cache.get(&k3).is_some());

        // Removing all leaves empty head/tail and 0 bytes.
        assert!(cache.remove(&k1));
        assert!(cache.remove(&k3));
        assert!(cache.is_empty());
        assert_eq!(cache.current_bytes(), 0);
        assert_eq!(cache.head, None);
        assert_eq!(cache.tail, None);
    }

    #[test]
    fn intrusive_lru_expires_by_ttl() {
        let mut cache = ByteBoundedLru::new(4096, Duration::from_millis(20));
        let k1 = *blake3::hash(b"exp").as_bytes();
        assert!(cache.insert(k1, Arc::from(vec![7u8; 64].into_boxed_slice())));
        std::thread::sleep(Duration::from_millis(35));
        assert!(cache.get(&k1).is_none());
        assert_eq!(cache.current_bytes(), 0);
        assert_eq!(cache.head, None);
        assert_eq!(cache.tail, None);
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

        let ranked = idx.ranked_candidates(&sk, &h_cur, 105_000);
        assert_eq!(ranked[0], h_small);

        let ranked_exact = idx.ranked_candidates(&sk, &h_big, 500_000);
        assert_eq!(ranked_exact[0], h_big);
    }
}
