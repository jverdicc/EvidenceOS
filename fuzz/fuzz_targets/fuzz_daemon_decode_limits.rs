#![no_main]

use evidenceos_daemon::auth::decode_with_max_size;
use evidenceos_protocol::pb;
use libfuzzer_sys::fuzz_target;
use prost::Message;

fuzz_target!(|data: &[u8]| {
    let max = data.len().saturating_sub(1);
    let _ = decode_with_max_size::<pb::CreateClaimV2Request>(data, max);

    if let Ok(msg) = pb::CreateClaimV2Request::decode(data) {
        let mut encoded = Vec::new();
        if msg.encode(&mut encoded).is_ok() {
            let exact = encoded.len();
            let _ = decode_with_max_size::<pb::CreateClaimV2Request>(&encoded, exact);
            let _ = decode_with_max_size::<pb::CreateClaimV2Request>(&encoded, exact.saturating_sub(1));
        }
    }
});
