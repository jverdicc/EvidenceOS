use crate::error::{EvidenceOSError, EvidenceOSResult};
use serde_json::{Map, Number, Value};

const SCHEMA_ID: &str = "cbrn/v1";
const LEGACY_SCHEMA_ID: &str = "legacy/v1";
const MAX_REFERENCES: usize = 16;
const MAX_REFERENCE_BYTES: usize = 128;
const MAX_SUBSTANCE_BYTES: usize = 64;

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

fn read_required_string<'a>(obj: &'a Map<String, Value>, key: &str) -> EvidenceOSResult<&'a str> {
    obj.get(key)
        .and_then(Value::as_str)
        .ok_or(EvidenceOSError::InvalidArgument)
}

fn read_required_u64(obj: &Map<String, Value>, key: &str) -> EvidenceOSResult<u64> {
    let number = obj
        .get(key)
        .and_then(Value::as_number)
        .ok_or(EvidenceOSError::InvalidArgument)?;
    if number.is_f64() {
        return Err(EvidenceOSError::InvalidArgument);
    }
    number.as_u64().ok_or(EvidenceOSError::InvalidArgument)
}

pub fn validate_and_canonicalize(
    output_schema_id: &str,
    payload: &[u8],
) -> EvidenceOSResult<StructuredClaimValidation> {
    if output_schema_id == LEGACY_SCHEMA_ID {
        return Ok(StructuredClaimValidation {
            canonical_bytes: payload.to_vec(),
            kout_bits_upper_bound: kout_bits_upper_bound(payload),
            max_bytes_upper_bound: max_bytes_upper_bound(),
        });
    }
    if output_schema_id != SCHEMA_ID {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let parsed: Value =
        serde_json::from_slice(payload).map_err(|_| EvidenceOSError::InvalidArgument)?;
    let Value::Object(obj) = parsed else {
        return Err(EvidenceOSError::InvalidArgument);
    };

    let schema_version = read_required_string(&obj, "schema_version")?;
    if schema_version != "1" {
        return Err(EvidenceOSError::InvalidArgument);
    }

    let substance = read_required_string(&obj, "substance")?;
    if substance.is_empty() || substance.len() > MAX_SUBSTANCE_BYTES {
        return Err(EvidenceOSError::InvalidArgument);
    }

    let unit = read_required_string(&obj, "unit")?;
    if !ALLOWED_UNITS.contains(&unit) {
        return Err(EvidenceOSError::InvalidArgument);
    }

    let reason_code = read_required_string(&obj, "reason_code")?;
    if !ALLOWED_REASON_CODES.contains(&reason_code) {
        return Err(EvidenceOSError::InvalidArgument);
    }

    let value = read_required_u64(&obj, "value")?;
    let confidence_bps = read_required_u64(&obj, "confidence_bps")?;
    if confidence_bps > 10_000 {
        return Err(EvidenceOSError::InvalidArgument);
    }

    let references = obj
        .get("references")
        .and_then(Value::as_array)
        .ok_or(EvidenceOSError::InvalidArgument)?;
    if references.len() > MAX_REFERENCES {
        return Err(EvidenceOSError::InvalidArgument);
    }

    let mut canonical_refs = Vec::with_capacity(references.len());
    for reference in references {
        let reference = reference.as_str().ok_or(EvidenceOSError::InvalidArgument)?;
        if reference.is_empty() || reference.len() > MAX_REFERENCE_BYTES {
            return Err(EvidenceOSError::InvalidArgument);
        }
        canonical_refs.push(reference.to_string());
    }

    for key in obj.keys() {
        if !matches!(
            key.as_str(),
            "schema_version"
                | "substance"
                | "unit"
                | "value"
                | "confidence_bps"
                | "reason_code"
                | "references"
        ) {
            return Err(EvidenceOSError::InvalidArgument);
        }
    }

    let canonical = Value::Object(Map::from_iter([
        (
            "confidence_bps".to_string(),
            Value::Number(Number::from(confidence_bps)),
        ),
        (
            "reason_code".to_string(),
            Value::String(reason_code.to_string()),
        ),
        (
            "references".to_string(),
            Value::Array(canonical_refs.into_iter().map(Value::String).collect()),
        ),
        ("schema_version".to_string(), Value::String("1".to_string())),
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
    let refs_budget = (MAX_REFERENCES * MAX_REFERENCE_BYTES) as u32;
    256 + refs_budget
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validates_and_canonicalizes() {
        let payload = json!({
            "schema_version":"1",
            "substance":"chlorine",
            "unit":"ppm",
            "value":2,
            "confidence_bps":9950,
            "reason_code":"ALERT",
            "references":["ref-a","ref-b"]
        });
        let result =
            validate_and_canonicalize("cbrn/v1", &serde_json::to_vec(&payload).expect("json"))
                .expect("valid");
        assert!(result.kout_bits_upper_bound >= 8);
        let second =
            validate_and_canonicalize("cbrn/v1", &result.canonical_bytes).expect("re-validate");
        assert_eq!(result.canonical_bytes, second.canonical_bytes);
    }

    #[test]
    fn rejects_float_numeric_fields() {
        let payload = json!({
            "schema_version":"1",
            "substance":"chlorine",
            "unit":"ppm",
            "value":1.2,
            "confidence_bps":9950,
            "reason_code":"ALERT",
            "references":["r"]
        });
        assert!(
            validate_and_canonicalize("cbrn/v1", &serde_json::to_vec(&payload).expect("json"))
                .is_err()
        );
    }
}
