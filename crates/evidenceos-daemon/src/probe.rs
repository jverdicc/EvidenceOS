use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeVerdict {
    Clean,
    Throttle {
        reason: &'static str,
        retry_after_ms: u64,
    },
    Escalate {
        reason: &'static str,
    },
    Freeze {
        reason: &'static str,
    },
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub window_ms: u64,
    pub throttle_total_requests: usize,
    pub throttle_unique_semantic_hashes: usize,
    pub throttle_distinct_topics: usize,
    pub escalate_total_requests: usize,
    pub escalate_unique_semantic_hashes: usize,
    pub escalate_distinct_topics: usize,
    pub freeze_total_requests: usize,
    pub freeze_unique_semantic_hashes: usize,
    pub freeze_distinct_topics: usize,
    pub throttle_retry_after_ms: u64,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            window_ms: 30_000,
            throttle_total_requests: 20,
            throttle_unique_semantic_hashes: 10,
            throttle_distinct_topics: 4,
            escalate_total_requests: 40,
            escalate_unique_semantic_hashes: 20,
            escalate_distinct_topics: 8,
            freeze_total_requests: 80,
            freeze_unique_semantic_hashes: 40,
            freeze_distinct_topics: 12,
            throttle_retry_after_ms: 3_000,
        }
    }
}

impl ProbeConfig {
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        cfg.window_ms = read_env_u64("EVIDENCEOS_PROBE_WINDOW_MS", cfg.window_ms);
        cfg.throttle_total_requests = read_env_usize(
            "EVIDENCEOS_PROBE_THROTTLE_TOTAL",
            cfg.throttle_total_requests,
        );
        cfg.throttle_unique_semantic_hashes = read_env_usize(
            "EVIDENCEOS_PROBE_THROTTLE_UNIQUE_SEMANTIC",
            cfg.throttle_unique_semantic_hashes,
        );
        cfg.throttle_distinct_topics = read_env_usize(
            "EVIDENCEOS_PROBE_THROTTLE_DISTINCT_TOPICS",
            cfg.throttle_distinct_topics,
        );
        cfg.escalate_total_requests = read_env_usize(
            "EVIDENCEOS_PROBE_ESCALATE_TOTAL",
            cfg.escalate_total_requests,
        );
        cfg.escalate_unique_semantic_hashes = read_env_usize(
            "EVIDENCEOS_PROBE_ESCALATE_UNIQUE_SEMANTIC",
            cfg.escalate_unique_semantic_hashes,
        );
        cfg.escalate_distinct_topics = read_env_usize(
            "EVIDENCEOS_PROBE_ESCALATE_DISTINCT_TOPICS",
            cfg.escalate_distinct_topics,
        );
        cfg.freeze_total_requests =
            read_env_usize("EVIDENCEOS_PROBE_FREEZE_TOTAL", cfg.freeze_total_requests);
        cfg.freeze_unique_semantic_hashes = read_env_usize(
            "EVIDENCEOS_PROBE_FREEZE_UNIQUE_SEMANTIC",
            cfg.freeze_unique_semantic_hashes,
        );
        cfg.freeze_distinct_topics = read_env_usize(
            "EVIDENCEOS_PROBE_FREEZE_DISTINCT_TOPICS",
            cfg.freeze_distinct_topics,
        );
        cfg.throttle_retry_after_ms = read_env_u64(
            "EVIDENCEOS_PROBE_THROTTLE_RETRY_AFTER_MS",
            cfg.throttle_retry_after_ms,
        );
        cfg
    }
}

fn read_env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

fn read_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

#[derive(Debug, Clone)]
pub struct ProbeObservation {
    pub principal_id: String,
    pub operation_id: String,
    pub topic_id: String,
    pub semantic_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProbeEvent {
    at_ms: u64,
    semantic_hash: String,
    topic_id: String,
}

#[derive(Debug, Clone, Default)]
struct ProbeWindowState {
    events: VecDeque<ProbeEvent>,
    total_requests_window: usize,
    semantic_counts: HashMap<String, usize>,
    topic_counts: HashMap<String, usize>,
}

impl ProbeWindowState {
    fn trim(&mut self, cutoff_ms: u64) {
        while let Some(front) = self.events.front() {
            if front.at_ms > cutoff_ms {
                break;
            }
            let _ = self.events.pop_front();
        }
        self.rebuild_counts();
    }

    fn observe(&mut self, at_ms: u64, semantic_hash: &str, topic_id: &str) {
        self.events.push_back(ProbeEvent {
            at_ms,
            semantic_hash: semantic_hash.to_string(),
            topic_id: topic_id.to_string(),
        });
        self.rebuild_counts();
    }

    fn rebuild_counts(&mut self) {
        self.total_requests_window = self.events.len();
        self.semantic_counts.clear();
        self.topic_counts.clear();
        for event in &self.events {
            *self
                .semantic_counts
                .entry(event.semantic_hash.clone())
                .or_insert(0) += 1;
            *self.topic_counts.entry(event.topic_id.clone()).or_insert(0) += 1;
        }
    }

    fn unique_semantic_hashes_window(&self) -> usize {
        self.semantic_counts.len()
    }

    fn distinct_topics_window(&self) -> usize {
        self.topic_counts.len()
    }
}

pub trait ProbeClock: Send + Sync {
    fn now_ms(&self) -> u64;
}

#[derive(Default)]
pub struct SystemClock;

impl ProbeClock for SystemClock {
    fn now_ms(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|v| v.as_millis() as u64)
            .unwrap_or(0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeSnapshot {
    pub total_requests_window: usize,
    pub unique_semantic_hashes_window: usize,
    pub distinct_topics_window: usize,
}

#[derive(Debug)]
pub struct ProbeDetector {
    cfg: ProbeConfig,
    principal_state: HashMap<String, ProbeWindowState>,
    operation_state: HashMap<(String, String), ProbeWindowState>,
}

impl ProbeDetector {
    pub fn new(cfg: ProbeConfig) -> Self {
        Self {
            cfg,
            principal_state: HashMap::new(),
            operation_state: HashMap::new(),
        }
    }

    pub fn observe(
        &mut self,
        obs: &ProbeObservation,
        now_ms: u64,
    ) -> (ProbeVerdict, ProbeSnapshot) {
        let cutoff = now_ms.saturating_sub(self.cfg.window_ms);

        let principal_bucket = self
            .principal_state
            .entry(obs.principal_id.clone())
            .or_default();
        principal_bucket.trim(cutoff);
        principal_bucket.observe(now_ms, &obs.semantic_hash, &obs.topic_id);

        let op_bucket = self
            .operation_state
            .entry((obs.principal_id.clone(), obs.operation_id.clone()))
            .or_default();
        op_bucket.trim(cutoff);
        op_bucket.observe(now_ms, &obs.semantic_hash, &obs.topic_id);

        let snapshot = ProbeSnapshot {
            total_requests_window: principal_bucket
                .total_requests_window
                .max(op_bucket.total_requests_window),
            unique_semantic_hashes_window: principal_bucket
                .unique_semantic_hashes_window()
                .max(op_bucket.unique_semantic_hashes_window()),
            distinct_topics_window: principal_bucket
                .distinct_topics_window()
                .max(op_bucket.distinct_topics_window()),
        };

        let verdict = evaluate(&self.cfg, &snapshot);
        (verdict, snapshot)
    }
}

fn evaluate(cfg: &ProbeConfig, snap: &ProbeSnapshot) -> ProbeVerdict {
    if snap.total_requests_window >= cfg.freeze_total_requests
        || snap.unique_semantic_hashes_window >= cfg.freeze_unique_semantic_hashes
        || snap.distinct_topics_window >= cfg.freeze_distinct_topics
    {
        return ProbeVerdict::Freeze {
            reason: "probe_freeze_threshold",
        };
    }
    if snap.total_requests_window >= cfg.escalate_total_requests
        || snap.unique_semantic_hashes_window >= cfg.escalate_unique_semantic_hashes
        || snap.distinct_topics_window >= cfg.escalate_distinct_topics
    {
        return ProbeVerdict::Escalate {
            reason: "probe_escalate_threshold",
        };
    }
    if snap.total_requests_window >= cfg.throttle_total_requests
        || snap.unique_semantic_hashes_window >= cfg.throttle_unique_semantic_hashes
        || snap.distinct_topics_window >= cfg.throttle_distinct_topics
    {
        return ProbeVerdict::Throttle {
            reason: "probe_throttle_threshold",
            retry_after_ms: cfg.throttle_retry_after_ms.max(1),
        };
    }
    ProbeVerdict::Clean
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn cfg() -> ProbeConfig {
        ProbeConfig {
            window_ms: 100,
            throttle_total_requests: 3,
            throttle_unique_semantic_hashes: 3,
            throttle_distinct_topics: 2,
            escalate_total_requests: 5,
            escalate_unique_semantic_hashes: 5,
            escalate_distinct_topics: 3,
            freeze_total_requests: 7,
            freeze_unique_semantic_hashes: 7,
            freeze_distinct_topics: 4,
            throttle_retry_after_ms: 50,
        }
    }

    fn obs(sem: &str, topic: &str) -> ProbeObservation {
        ProbeObservation {
            principal_id: "p".to_string(),
            operation_id: "o".to_string(),
            topic_id: topic.to_string(),
            semantic_hash: sem.to_string(),
        }
    }

    #[test]
    fn threshold_boundaries() {
        let mut d = ProbeDetector::new(cfg());
        assert!(matches!(
            d.observe(&obs("a", "t1"), 1).0,
            ProbeVerdict::Clean
        ));
        assert!(matches!(
            d.observe(&obs("a", "t1"), 2).0,
            ProbeVerdict::Clean
        ));
        assert!(matches!(
            d.observe(&obs("a", "t1"), 3).0,
            ProbeVerdict::Throttle { .. }
        ));
        assert!(matches!(
            d.observe(&obs("a", "t1"), 4).0,
            ProbeVerdict::Throttle { .. }
        ));
        assert!(matches!(
            d.observe(&obs("a", "t1"), 5).0,
            ProbeVerdict::Escalate { .. }
        ));
        assert!(matches!(
            d.observe(&obs("a", "t1"), 6).0,
            ProbeVerdict::Escalate { .. }
        ));
        assert!(matches!(
            d.observe(&obs("a", "t1"), 7).0,
            ProbeVerdict::Freeze { .. }
        ));
    }

    #[test]
    fn window_expiry_and_cooldown() {
        let mut d = ProbeDetector::new(cfg());
        let _ = d.observe(&obs("a", "t1"), 1);
        let _ = d.observe(&obs("a", "t1"), 2);
        let (v, _) = d.observe(&obs("a", "t1"), 3);
        assert!(matches!(v, ProbeVerdict::Throttle { .. }));
        let (v2, _) = d.observe(&obs("a", "t1"), 500);
        assert!(matches!(v2, ProbeVerdict::Clean));
    }

    #[test]
    fn diversity_counts() {
        let mut d = ProbeDetector::new(cfg());
        let _ = d.observe(&obs("same", "t1"), 1);
        let _ = d.observe(&obs("same", "t1"), 2);
        let (v, snap) = d.observe(&obs("same", "t1"), 3);
        assert!(matches!(v, ProbeVerdict::Throttle { .. }));
        assert_eq!(snap.unique_semantic_hashes_window, 1);

        let mut d2 = ProbeDetector::new(cfg());
        let _ = d2.observe(&obs("a", "t1"), 1);
        let _ = d2.observe(&obs("b", "t1"), 2);
        let (_v2, snap2) = d2.observe(&obs("c", "t1"), 3);
        assert_eq!(snap2.unique_semantic_hashes_window, 3);
    }

    #[test]
    fn deterministic_sequence() {
        let mut a = ProbeDetector::new(cfg());
        let mut b = ProbeDetector::new(cfg());
        let seq = [obs("a", "t1"), obs("b", "t2"), obs("c", "t2")];
        for (i, item) in seq.iter().enumerate() {
            let out_a = a.observe(item, i as u64 + 1);
            let out_b = b.observe(item, i as u64 + 1);
            assert_eq!(format!("{:?}", out_a.0), format!("{:?}", out_b.0));
            assert_eq!(out_a.1.total_requests_window, out_b.1.total_requests_window);
        }
    }

    proptest! {
        #[test]
        fn detector_invariants(events in proptest::collection::vec((0u64..20u64, 0u8..4u8, 0u8..4u8), 1..64)) {
            let mut detector = ProbeDetector::new(cfg());
            let mut now = 0u64;
            for (delta, sem, topic) in events {
                now = now.saturating_add(delta);
                let event = ProbeObservation {
                    principal_id: "principal".to_string(),
                    operation_id: "op".to_string(),
                    topic_id: format!("t{topic}"),
                    semantic_hash: format!("s{sem}"),
                };
                let (verdict, snapshot) = detector.observe(&event, now);
                if let ProbeVerdict::Throttle { retry_after_ms, .. } = verdict {
                    prop_assert!(retry_after_ms > 0);
                }
                prop_assert!(snapshot.total_requests_window <= 64);
                prop_assert!(snapshot.unique_semantic_hashes_window <= 64);
                prop_assert!(snapshot.distinct_topics_window <= 64);
            }
        }
    }
}
