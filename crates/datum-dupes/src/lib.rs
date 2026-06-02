use std::num::NonZeroUsize;

use lru::LruCache;
use parking_lot::Mutex;

/// Composite share-dedup key. Generic over channel/connection identifier so SV1
/// uses (connection_id, job_id, …) and SV2 uses (channel_id, sequence_number, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShareKey {
    pub channel_id: u32,
    pub sequence: u64,
    pub ntime: u32,
    pub version: u32,
    pub extranonce: u128,
    pub nonce: u32,
}

/// Bounded LRU dedup cache. Replaces the C SV1-sizing formula
/// `max_clients × target_shares × stale_min × 16` (which over-allocates by
/// `max_channels_per_connection`× under SV2 — see the wiki article on
/// dupe-table sizing).
pub struct DupeCache {
    inner: Mutex<LruCache<ShareKey, ()>>,
}

impl DupeCache {
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: Mutex::new(LruCache::new(cap)),
        }
    }

    /// Returns `true` if the share is novel (was not in the cache); `false` if
    /// it's a duplicate. Insert side-effect: novel shares become MRU; existing
    /// shares are touched-as-MRU to prevent eviction of recent active streams.
    pub fn check_and_insert(&self, key: ShareKey) -> bool {
        let mut g = self.inner.lock();
        if g.get(&key).is_some() {
            return false;
        }
        g.put(key, ());
        true
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.inner.lock().cap().get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seq: u64) -> ShareKey {
        ShareKey {
            channel_id: 1,
            sequence: seq,
            ntime: 0x1700_0000,
            version: 0x2000_0000,
            extranonce: 0xdeadbeef,
            nonce: seq as u32,
        }
    }

    #[test]
    fn first_insert_is_novel() {
        let c = DupeCache::new(64);
        assert!(c.check_and_insert(key(1)));
    }

    #[test]
    fn second_insert_of_same_key_is_dupe() {
        let c = DupeCache::new(64);
        c.check_and_insert(key(1));
        assert!(!c.check_and_insert(key(1)));
    }

    #[test]
    fn distinct_keys_are_novel() {
        let c = DupeCache::new(64);
        assert!(c.check_and_insert(key(1)));
        assert!(c.check_and_insert(key(2)));
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn capacity_evicts_lru() {
        let c = DupeCache::new(2);
        c.check_and_insert(key(1));
        c.check_and_insert(key(2));
        c.check_and_insert(key(3));
        assert_eq!(c.len(), 2);
        assert!(c.check_and_insert(key(1)));
    }

    #[test]
    fn capacity_zero_clamps_to_one() {
        let c = DupeCache::new(0);
        assert_eq!(c.capacity(), 1);
        assert!(c.check_and_insert(key(1)));
    }

    #[test]
    fn touch_keeps_recently_seen() {
        let c = DupeCache::new(2);
        c.check_and_insert(key(1));
        c.check_and_insert(key(2));
        assert!(!c.check_and_insert(key(1)));
        c.check_and_insert(key(3));
        assert!(!c.check_and_insert(key(1)));
        assert!(c.check_and_insert(key(2)));
    }
}
