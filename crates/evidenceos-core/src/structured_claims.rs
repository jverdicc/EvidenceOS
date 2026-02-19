use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde_json::{Map, Number, Value};

pub const SCHEMA_ID: &str = "cbrn-sc.v1";
pub const SCHEMA_ID_ALIAS: &str = "cbrn/v1";
pub const LEGACY_SCHEMA_ID: &str = "legacy/v1";

const SCHEMA_ALIASES: &[&str] = &[
    SCHEMA_ID,
    SCHEMA_ID_ALIAS,
    "schema/v1",
    "cbrn_sc.v1",
    "cbrn-sc/v1",
];

const MAX_REFERENCES: usize = 16;
const MAX_REFERENCE_BYTES: usize = 128;
const MAX_STR_BYTES: usize = 128;
const MAX_REASON_CODES: usize = 8;

const ALLOWED_UNITS: &[&str] = &["ppm", "ppb", "ug/m3", "mg/m3", "bq/m3"];
const ALLOWED_REASON_CODES: &[&str] = &[
    "NORMAL",
    "WATCH",
    "ALERT",
    "CRITICAL",
    "INSTRUMENT_FAULT",
    "INSUFFICIENT_EVIDENCE",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredClaimValidation {
    pub canonical_bytes: Vec<u8>,
    pub kout_bits_upper_bound: u64,
    pub max_bytes_upper_bound: u32,
}

fn reject_floats(value: &Value) -> EvidenceOSResult<()> {
    match value {
        Value::Number(n) => {
            if n.is_f64() {
                return Err(EvidenceOSError::InvalidArgument);
            }
            Ok(())
        }
        Value::Array(xs) => xs.iter().try_for_each(reject_floats),
        Value::Object(m) => m.values().try_for_each(reject_floats),
        _ => Ok(()),
    }
}

fn read_required_string<'a>(obj: &'a Map<String, Value>, key: &str) -> EvidenceOSResult<&'a str> {
    let v = obj
        .get(key)
        .and_then(Value::as_str)
        .ok_or(EvidenceOSError::InvalidArgument)?;
    if v.is_empty() || v.len() > MAX_STR_BYTES {
        return Err(EvidenceOSError::InvalidArgument);
    }
    Ok(v)
}

fn read_required_u64(obj: &Map<String, Value>, key: &str) -> EvidenceOSResult<u64> {
    let n = obj
        .get(key)
        .and_then(Value::as_number)
        .ok_or(EvidenceOSError::InvalidArgument)?;
    if n.is_f64() {
        return Err(EvidenceOSError::InvalidArgument);
    }
    n.as_u64().ok_or(EvidenceOSError::InvalidArgument)
}

pub fn canonicalize_schema_id(output_schema_id: &str) -> EvidenceOSResult<&'static str> {
    if output_schema_id == LEGACY_SCHEMA_ID {
        return Ok(LEGACY_SCHEMA_ID);
    }
    if SCHEMA_ALIASES.contains(&output_schema_id) {
        return Ok(SCHEMA_ID);
    }
    Err(EvidenceOSError::InvalidArgument)
}
pub fn validate_and_canonicalize(
    output_schema_id: &str,
    payload: &[u8],
) -> EvidenceOSResult<StructuredClaimValidation> {
    let canonical_schema_id = canonicalize_schema_id(output_schema_id)?;
    if canonical_schema_id == LEGACY_SCHEMA_ID {
        return Ok(StructuredClaimValidation {
            canonical_bytes: payload.to_vec(),
            kout_bits_upper_bound: kout_bits_upper_bound(payload),
            max_bytes_upper_bound: max_bytes_upper_bound(),
        });
    }
    let parsed: Value =
        serde_json::from_slice(payload).map_err(|_| EvidenceOSError::InvalidArgument)?;
    reject_floats(&parsed)?;
    let Value::Object(obj) = parsed else {
        return Err(EvidenceOSError::InvalidArgument);
    };

    let allowed = [
        "schema_version",
        "claim_id",
        "event_time_unix",
        "substance",
        "unit",
        "value",
        "confidence_bps",
        "reason_code",
        "reason_codes",
        "references",
        "location_id",
        "sensor_id",
    ];
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(EvidenceOSError::InvalidArgument);
        }
    }

    let schema_version = read_required_string(&obj, "schema_version")?;
    if schema_version != "1" {
        return Err(EvidenceOSError::InvalidArgument);
    }

    let claim_id = read_required_string(&obj, "claim_id")?;
    let event_time_unix = read_required_u64(&obj, "event_time_unix")?;
    let substance = read_required_string(&obj, "substance")?;
    let unit = read_required_string(&obj, "unit")?;
    if !ALLOWED_UNITS.contains(&unit) {
        return Err(EvidenceOSError::InvalidArgument);
    }

    let value = read_required_u64(&obj, "value")?;
    if value > 1_000_000_000 {
        return Err(EvidenceOSError::InvalidArgument);
    }

    let confidence_bps = read_required_u64(&obj, "confidence_bps")?;
    if confidence_bps > 10_000 {
        return Err(EvidenceOSError::InvalidArgument);
    }

    let reason_code = read_required_string(&obj, "reason_code")?;
    if !ALLOWED_REASON_CODES.contains(&reason_code) {
        return Err(EvidenceOSError::InvalidArgument);
    }

    let reason_codes = obj
        .get("reason_codes")
        .and_then(Value::as_array)
        .ok_or(EvidenceOSError::InvalidArgument)?;
    if reason_codes.is_empty() || reason_codes.len() > MAX_REASON_CODES {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let mut canonical_reason_codes = Vec::with_capacity(reason_codes.len());
    for code in reason_codes {
        let code = code.as_str().ok_or(EvidenceOSError::InvalidArgument)?;
        if !ALLOWED_REASON_CODES.contains(&code) {
            return Err(EvidenceOSError::InvalidArgument);
        }
        canonical_reason_codes.push(code.to_string());
    }

    let references = obj
        .get("references")
        .and_then(Value::as_array)
        .ok_or(EvidenceOSError::InvalidArgument)?;
    if references.len() > MAX_REFERENCES {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let mut canonical_refs = Vec::with_capacity(references.len());
    for r in references {
        let r = r.as_str().ok_or(EvidenceOSError::InvalidArgument)?;
        if r.is_empty() || r.len() > MAX_REFERENCE_BYTES {
            return Err(EvidenceOSError::InvalidArgument);
        }
        canonical_refs.push(r.to_string());
    }

    let location_id = read_required_string(&obj, "location_id")?;
    let sensor_id = read_required_string(&obj, "sensor_id")?;

    let canonical = Value::Object(Map::from_iter([
        ("claim_id".to_string(), Value::String(claim_id.to_string())),
        (
            "confidence_bps".to_string(),
            Value::Number(Number::from(confidence_bps)),
        ),
        (
            "event_time_unix".to_string(),
            Value::Number(Number::from(event_time_unix)),
        ),
        (
            "location_id".to_string(),
            Value::String(location_id.to_string()),
        ),
        (
            "reason_code".to_string(),
            Value::String(reason_code.to_string()),
        ),
        (
            "reason_codes".to_string(),
            Value::Array(
                canonical_reason_codes
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        ),
        (
            "references".to_string(),
            Value::Array(canonical_refs.into_iter().map(Value::String).collect()),
        ),
        ("schema_version".to_string(), Value::String("1".to_string())),
        (
            "sensor_id".to_string(),
            Value::String(sensor_id.to_string()),
        ),
        (
            "substance".to_string(),
            Value::String(substance.to_string()),
        ),
        ("unit".to_string(), Value::String(unit.to_string())),
        ("value".to_string(), Value::Number(Number::from(value))),
    ]));

    let canonical_bytes = serde_json::to_vec(&canonical).map_err(|_| EvidenceOSError::Internal)?;
    Ok(StructuredClaimValidation {
        kout_bits_upper_bound: kout_bits_upper_bound(&canonical_bytes),
        max_bytes_upper_bound: max_bytes_upper_bound(),
        canonical_bytes,
    })
}

pub fn kout_bits_upper_bound(canonical_bytes: &[u8]) -> u64 {
    (canonical_bytes.len() as u64).saturating_mul(8)
}

pub fn max_bytes_upper_bound() -> u32 {
    (512 + (MAX_REFERENCES * MAX_REFERENCE_BYTES)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn valid_payload() -> Value {
        json!({
            "schema_version":"1",
            "claim_id":"c-1",
            "event_time_unix":1700000000,
            "substance":"chlorine",
            "unit":"ppm",
            "value":2,
            "confidence_bps":9950,
            "reason_code":"ALERT",
            "reason_codes":["ALERT", "WATCH"],
            "references":["ref-a","ref-b"],
            "location_id":"loc-1",
            "sensor_id":"sensor-1"
        })
    }

    #[test]
    fn validates_and_canonicalizes_cbrn_sc() {
        let payload = serde_json::to_vec(&valid_payload()).expect("json");
        let first = validate_and_canonicalize(SCHEMA_ID, &payload).expect("valid");
        let second =
            validate_and_canonicalize(SCHEMA_ID, &first.canonical_bytes).expect("re-validate");
        assert_eq!(first.canonical_bytes, second.canonical_bytes);
        assert!(first.kout_bits_upper_bound > 0);
    }

    #[test]
    fn accepts_alias_schema_id() {
        let payload = serde_json::to_vec(&valid_payload()).expect("json");
        for alias in [SCHEMA_ID_ALIAS, "schema/v1", "cbrn_sc.v1", "cbrn-sc/v1"] {
            assert!(validate_and_canonicalize(alias, &payload).is_ok());
            assert_eq!(
                canonicalize_schema_id(alias).expect("canonical alias"),
                SCHEMA_ID
            );
        }
    }

    #[test]
    fn rejects_float_anywhere() {
        let mut payload = valid_payload();
        payload["value"] = json!(1.25);
        let bytes = serde_json::to_vec(&payload).expect("json");
        assert!(validate_and_canonicalize(SCHEMA_ID, &bytes).is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut payload = valid_payload();
        payload["unknown"] = json!(1);
        let bytes = serde_json::to_vec(&payload).expect("json");
        assert!(validate_and_canonicalize(SCHEMA_ID, &bytes).is_err());
    }

    #[test]
    fn legacy_bypass_round_trips_bytes() {
        let raw = vec![0x01];
        let out = validate_and_canonicalize(LEGACY_SCHEMA_ID, &raw).expect("legacy");
        assert_eq!(out.canonical_bytes, raw);
    }

    proptest! {
        #[test]
        fn cbrn_sc_roundtrip_proptest(value in 0u64..10000u64, conf in 0u64..10000u64) {
            let payload = json!({
                "schema_version":"1",
                "claim_id":"c-1",
                "event_time_unix":1700000000,
                "substance":"chlorine",
                "unit":"ppm",
                "value":value,
                "confidence_bps":conf,
                "reason_code":"ALERT",
                "reason_codes":["ALERT"],
                "references":["ref-a"],
                "location_id":"loc-1",
                "sensor_id":"sensor-1"
            });
            let bytes = serde_json::to_vec(&payload).expect("json");
            let first = validate_and_canonicalize(SCHEMA_ID, &bytes).expect("valid");
            let second = validate_and_canonicalize(SCHEMA_ID, &first.canonical_bytes).expect("re-validate");
            prop_assert_eq!(first.canonical_bytes, second.canonical_bytes);
        }
    }
}
