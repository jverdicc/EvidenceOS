#![no_main]

use arbitrary::Arbitrary;
use evidenceos_daemon::probe::{ProbeConfig, ProbeDetector, ProbeObservation, ProbeVerdict};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Event {
    delta_ms: u16,
    principal: u8,
    operation: u8,
    topic: u8,
    semantic: u8,
}

fuzz_target!(|events: Vec<Event>| {
    let mut detector = ProbeDetector::new(ProbeConfig::default());
    let mut now = 0u64;
    for e in events {
        now = now.saturating_add(u64::from(e.delta_ms));
        let obs = ProbeObservation {
            principal_id: format!("p{}", e.principal),
            operation_id: format!("o{}", e.operation),
            topic_id: format!("t{}", e.topic),
            semantic_hash: format!("s{}", e.semantic),
        };
        let (verdict, _snap) = detector.observe(&obs, now);
        match verdict {
            ProbeVerdict::Clean
            | ProbeVerdict::Escalate { .. }
            | ProbeVerdict::Freeze { .. } => {}
            ProbeVerdict::Throttle { retry_after_ms, .. } => {
                assert!(retry_after_ms > 0);
            }
        }
    }
});
