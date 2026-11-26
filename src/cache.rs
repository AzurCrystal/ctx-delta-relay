use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// O(1)-amortized byte-bounded TTL LRU cache storing zstd-compressed payload snapshots.
/// Zero disk usage; strictly enforces `current_bytes <= max_bytes`.
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
    data: Arc<Vec<u8>>,
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

    /// Look up a cached compressed snapshot by BLAKE3 key; refreshes LRU position and TTL.
    pub fn get(&mut self, key: &[u8; 32]) -> Option<Arc<Vec<u8>>> {
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

    /// Insert or refresh a compressed snapshot while strictly keeping `current_bytes <= max_bytes`.
    pub fn insert(&mut self, key: [u8; 32], data: Arc<Vec<u8>>) -> bool {
        let size = data.len();
        if size == 0 || size > self.max_bytes {
            return false;
        }
        let now = Instant::now();
        self.purge_expired(now);

        if let Some(existing) = self.entries.remove(&key) {
            self.current_bytes = self.current_bytes.saturating_sub(existing.data.len());
        }

        while self.current_bytes + size > self.max_bytes {
            if !self.evict_oldest() {
                break;
            }
        }

        if self.current_bytes + size > self.max_bytes {
            return false;
        }

        let seq = self.alloc_seq();
        self.current_bytes += size;
        self.entries.insert(
            key,
            CacheEntry {
                data,
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
            self.current_bytes = self.current_bytes.saturating_sub(old.data.len());
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
                                self.current_bytes.saturating_sub(old.data.len());
                            removed += 1;
                        }
                    } else {
                        break;
                    }
                }
                _ => {
                    // Stale queue pointer from an earlier touch/removal.
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
                self.current_bytes = self.current_bytes.saturating_sub(old.data.len());
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

/// Sender-side lightweight index mapping a conversation fingerprint to up to 2 recent
/// snapshot hashes so even parallel/forked turns pick the best base snapshot.
pub struct SessionIndex {
    max_sessions: usize,
    ttl: Duration,
    sessions: HashMap<[u8; 32], SessionSlot>,
}

struct SessionSlot {
    recent_hashes: VecDeque<([u8; 32], usize, Instant)>,
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

    /// Return candidate base hashes (newest first, fresh within TTL) for a conversation key.
    pub fn candidates(&mut self, session_key: &[u8; 32]) -> Vec<[u8; 32]> {
        let now = Instant::now();
        let Some(slot) = self.sessions.get_mut(session_key) else {
            return Vec::new();
        };
        slot.recent_hashes
            .retain(|(_, _, ts)| now.saturating_duration_since(*ts) < self.ttl);
        if slot.recent_hashes.is_empty() {
            self.sessions.remove(session_key);
            return Vec::new();
        }
        slot.last_seen = now;
        slot.recent_hashes.iter().rev().map(|(h, _, _)| *h).collect()
    }

    /// Record that `full_hash` is now active for `session_key`.
    pub fn record(&mut self, session_key: [u8; 32], full_hash: [u8; 32], raw_len: usize) {
        let now = Instant::now();
        if self.sessions.len() >= self.max_sessions && !self.sessions.contains_key(&session_key) {
            self.evict_stale_or_oldest(now);
        }
        let slot = self.sessions.entry(session_key).or_insert_with(|| SessionSlot {
            recent_hashes: VecDeque::with_capacity(3),
            last_seen: now,
        });
        slot.last_seen = now;
        slot.recent_hashes.retain(|(h, _, _)| *h != full_hash);
        slot.recent_hashes.push_back((full_hash, raw_len, now));
        while slot.recent_hashes.len() > 2 {
            slot.recent_hashes.pop_front();
        }
    }

    /// Forget a hash across a session after a 409 Cache-Miss.
    pub fn invalidate_hash(&mut self, session_key: &[u8; 32], bad_hash: &[u8; 32]) {
        if let Some(slot) = self.sessions.get_mut(session_key) {
            slot.recent_hashes.retain(|(h, _, _)| h != bad_hash);
            if slot.recent_hashes.is_empty() {
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
    fn lru_enforces_hard_byte_cap_and_order() {
        let mut cache = ByteBoundedLru::new(250, Duration::from_secs(60));
        let k1 = *blake3::hash(b"1").as_bytes();
        let k2 = *blake3::hash(b"2").as_bytes();
        let k3 = *blake3::hash(b"3").as_bytes();

        assert!(cache.insert(k1, Arc::new(vec![1u8; 100])));
        assert!(cache.insert(k2, Arc::new(vec![2u8; 100])));
        assert_eq!(cache.current_bytes(), 200);

        // Touch k1 so k2 becomes the oldest.
        assert!(cache.get(&k1).is_some());

        // Inserting k3 (100 bytes) must evict k2, keeping k1 and k3.
        assert!(cache.insert(k3, Arc::new(vec![3u8; 100])));
        assert!(cache.current_bytes() <= 250);
        assert_eq!(cache.current_bytes(), 200);
        assert_eq!(cache.evictions(), 1);
        assert!(cache.get(&k1).is_some());
        assert!(cache.get(&k2).is_none());
        assert!(cache.get(&k3).is_some());
    }

    #[test]
    fn lru_expires_by_ttl() {
        let mut cache = ByteBoundedLru::new(1024, Duration::from_millis(20));
        let k1 = *blake3::hash(b"exp").as_bytes();
        assert!(cache.insert(k1, Arc::new(vec![7u8; 64])));
        std::thread::sleep(Duration::from_millis(35));
        assert!(cache.get(&k1).is_none());
        assert_eq!(cache.current_bytes(), 0);
    }
}
