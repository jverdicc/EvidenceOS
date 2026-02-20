use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::magnitude_envelope::{EnvelopeRegistry, EnvelopeViolation};
use crate::physhir::{check_dimension, parse_quantity, quantity_from_parts, Dimension, Quantity};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const SCHEMA_ID: &str = "cbrn-sc.v1";
pub const SCHEMA_ID_ALIAS: &str = "cbrn/v1";
pub const LEGACY_SCHEMA_ID: &str = "legacy/v1";
const MAX_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalFieldValue {
    Enum(String),
    Bool(bool),
    Int(i64),
    FixedPoint { value: i128, scale: i32 },
    Quantity(Quantity),
    Bytes(String),
}

impl CanonicalFieldValue {
    pub fn tag(&self) -> u8 {
        match self {
            Self::Enum(_) => 1,
            Self::Bool(_) => 2,
            Self::Int(_) => 3,
            Self::FixedPoint { .. } => 4,
            Self::Quantity(_) => 5,
            Self::Bytes(_) => 6,
        }
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            Self::Enum(v) | Self::Bytes(v) => v.as_bytes().to_vec(),
            Self::Bool(v) => vec![u8::from(*v)],
            Self::Int(v) => v.to_be_bytes().to_vec(),
            Self::FixedPoint { value, scale } => format!("{value}@{scale}").into_bytes(),
            Self::Quantity(q) => {
                format!("{}@{}:{}", q.value, q.scale, q.unit.canonical()).into_bytes()
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredField {
    pub name: String,
    pub value: CanonicalFieldValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredClaim {
    pub schema_id: String,
    pub fields: Vec<StructuredField>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StructuredClaimValidation {
    pub canonical_bytes: Vec<u8>,
    pub kout_bits_upper_bound: u64,
    pub max_bytes_upper_bound: u32,
    pub claim: StructuredClaim,
    pub envelope_violation: Option<EnvelopeViolation>,
}

#[derive(Clone)]
enum FieldType {
    Enum(&'static [&'static str]),
    Bool,
    IntRange {
        min: i64,
        max: i64,
    },
    FixedPointRange {
        min: i128,
        max: i128,
        scale_min: i32,
        scale_max: i32,
    },
    Quantity {
        expected_dim: Dimension,
        min: i128,
        max: i128,
    },
    Bytes {
        max: usize,
    },
}

#[derive(Clone)]
struct SchemaField {
    name: &'static str,
    required: bool,
    kind: FieldType,
}

#[derive(Clone)]
struct ClaimSchema {
    id: &'static str,
    fields: Vec<SchemaField>,
    max_total_bytes: usize,
}

pub struct SchemaRegistry;

impl SchemaRegistry {
    fn cbrn_v1() -> ClaimSchema {
        ClaimSchema {
            id: SCHEMA_ID,
            max_total_bytes: 1024,
            fields: vec![
                SchemaField {
                    name: "schema_id",
                    required: true,
                    kind: FieldType::Enum(&[SCHEMA_ID]),
                },
                SchemaField {
                    name: "claim_id",
                    required: true,
                    kind: FieldType::Bytes { max: 64 },
                },
                SchemaField {
                    name: "event_time_unix",
                    required: true,
                    kind: FieldType::IntRange {
                        min: 0,
                        max: 4_102_444_800,
                    },
                },
                SchemaField {
                    name: "sensor_id",
                    required: true,
                    kind: FieldType::Bytes { max: 64 },
                },
                SchemaField {
                    name: "location_id",
                    required: false,
                    kind: FieldType::Bytes { max: 64 },
                },
                SchemaField {
                    name: "reason_code",
                    required: true,
                    kind: FieldType::Enum(&[
                        "NORMAL",
                        "WATCH",
                        "ALERT",
                        "CRITICAL",
                        "INSTRUMENT_FAULT",
                        "INSUFFICIENT_EVIDENCE",
                    ]),
                },
                SchemaField {
                    name: "confidence_bps",
                    required: true,
                    kind: FieldType::IntRange {
                        min: 0,
                        max: 10_000,
                    },
                },
                SchemaField {
                    name: "requires_review",
                    required: false,
                    kind: FieldType::Bool,
                },
                SchemaField {
                    name: "measurement",
                    required: true,
                    kind: FieldType::Quantity {
                        expected_dim: Dimension::new(-3, 0, 0, 0, 0, 1, 0),
                        min: -9_999_999_999_999,
                        max: 9_999_999_999_999,
                    },
                },
                SchemaField {
                    name: "bounded_score",
                    required: false,
                    kind: FieldType::FixedPointRange {
                        min: 0,
                        max: 10_000,
                        scale_min: 0,
                        scale_max: 4,
                    },
                },
            ],
        }
    }

    fn legacy_v1() -> ClaimSchema {
        ClaimSchema {
            id: LEGACY_SCHEMA_ID,
            fields: Vec::new(),
            max_total_bytes: 0,
        }
    }

    fn get(schema_id: &str) -> Option<ClaimSchema> {
        match schema_id {
            SCHEMA_ID => Some(Self::cbrn_v1()),
            LEGACY_SCHEMA_ID => Some(Self::legacy_v1()),
            _ => None,
        }
    }
}

pub fn canonicalize_schema_id(output_schema_id: &str) -> EvidenceOSResult<&'static str> {
    if output_schema_id == LEGACY_SCHEMA_ID {
        return Ok(LEGACY_SCHEMA_ID);
    }
    if [
        SCHEMA_ID,
        SCHEMA_ID_ALIAS,
        "schema/v1",
        "cbrn_sc.v1",
        "cbrn-sc/v1",
    ]
    .contains(&output_schema_id)
    {
        return Ok(SCHEMA_ID);
    }
    Err(EvidenceOSError::InvalidArgument)
}

fn reject_floats_and_depth(value: &Value, depth: usize) -> EvidenceOSResult<()> {
    if depth > MAX_DEPTH {
        return Err(EvidenceOSError::InvalidArgument);
    }
    match value {
        Value::Number(n) if n.is_f64() => Err(EvidenceOSError::InvalidArgument),
        Value::Array(xs) => xs
            .iter()
            .try_for_each(|v| reject_floats_and_depth(v, depth + 1)),
        Value::Object(map) => map
            .values()
            .try_for_each(|v| reject_floats_and_depth(v, depth + 1)),
        _ => Ok(()),
    }
}

fn parse_fixed_point_obj(v: &Value) -> EvidenceOSResult<(i128, i32)> {
    let obj = v.as_object().ok_or(EvidenceOSError::InvalidArgument)?;
    let value = obj
        .get("value")
        .and_then(Value::as_str)
        .ok_or(EvidenceOSError::InvalidArgument)?;
    let scale = obj
        .get("scale")
        .and_then(Value::as_i64)
        .ok_or(EvidenceOSError::InvalidArgument)?;
    Ok((
        value
            .parse::<i128>()
            .map_err(|_| EvidenceOSError::InvalidArgument)?,
        i32::try_from(scale).map_err(|_| EvidenceOSError::InvalidArgument)?,
    ))
}

fn to_field(kind: &FieldType, name: &str, value: &Value) -> EvidenceOSResult<StructuredField> {
    let f = match kind {
        FieldType::Enum(allowed) => {
            let v = value.as_str().ok_or(EvidenceOSError::InvalidArgument)?;
            if !allowed.contains(&v) {
                return Err(EvidenceOSError::InvalidArgument);
            }
            CanonicalFieldValue::Enum(v.to_string())
        }
        FieldType::Bool => {
            CanonicalFieldValue::Bool(value.as_bool().ok_or(EvidenceOSError::InvalidArgument)?)
        }
        FieldType::IntRange { min, max } => {
            let v = value.as_i64().ok_or(EvidenceOSError::InvalidArgument)?;
            if v < *min || v > *max {
                return Err(EvidenceOSError::InvalidArgument);
            }
            CanonicalFieldValue::Int(v)
        }
        FieldType::FixedPointRange {
            min,
            max,
            scale_min,
            scale_max,
        } => {
            let (v, scale) = parse_fixed_point_obj(value)?;
            if v < *min || v > *max || scale < *scale_min || scale > *scale_max {
                return Err(EvidenceOSError::InvalidArgument);
            }
            CanonicalFieldValue::FixedPoint { value: v, scale }
        }
        FieldType::Quantity {
            expected_dim,
            min,
            max,
        } => {
            let q = if let Some(s) = value.as_str() {
                parse_quantity(s)?
            } else {
                let obj = value.as_object().ok_or(EvidenceOSError::InvalidArgument)?;
                let v = obj
                    .get("value")
                    .and_then(Value::as_str)
                    .ok_or(EvidenceOSError::InvalidArgument)?
                    .parse::<i128>()
                    .map_err(|_| EvidenceOSError::InvalidArgument)?;
                let scale = obj
                    .get("scale")
                    .and_then(Value::as_i64)
                    .ok_or(EvidenceOSError::InvalidArgument)?;
                let unit = obj
                    .get("unit")
                    .and_then(Value::as_str)
                    .ok_or(EvidenceOSError::InvalidArgument)?;
                quantity_from_parts(
                    v,
                    i32::try_from(scale).map_err(|_| EvidenceOSError::InvalidArgument)?,
                    unit,
                )?
            };
            check_dimension(&q, *expected_dim)?;
            if q.value < *min || q.value > *max {
                return Err(EvidenceOSError::InvalidArgument);
            }
            CanonicalFieldValue::Quantity(q)
        }
        FieldType::Bytes { max } => {
            let s = value.as_str().ok_or(EvidenceOSError::InvalidArgument)?;
            if s.is_empty() || s.len() > *max {
                return Err(EvidenceOSError::InvalidArgument);
            }
            CanonicalFieldValue::Bytes(s.to_string())
        }
    };
    Ok(StructuredField {
        name: name.to_string(),
        value: f,
    })
}

pub fn canonical_encode(claim: &StructuredClaim) -> EvidenceOSResult<Vec<u8>> {
    let mut out = Map::new();
    out.insert(
        "schema_id".to_string(),
        Value::String(claim.schema_id.clone()),
    );
    for field in &claim.fields {
        let value = match &field.value {
            CanonicalFieldValue::Enum(v) | CanonicalFieldValue::Bytes(v) => {
                Value::String(v.clone())
            }
            CanonicalFieldValue::Bool(v) => Value::Bool(*v),
            CanonicalFieldValue::Int(v) => Value::Number((*v).into()),
            CanonicalFieldValue::FixedPoint { value, scale } => {
                serde_json::json!({"scale": scale, "value": value.to_string()})
            }
            CanonicalFieldValue::Quantity(q) => {
                serde_json::json!({"scale": q.scale, "unit": q.unit.canonical(), "value": q.value.to_string()})
            }
        };
        out.insert(field.name.clone(), value);
    }
    serde_json::to_vec(&Value::Object(out)).map_err(|_| EvidenceOSError::Internal)
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
            claim: StructuredClaim {
                schema_id: LEGACY_SCHEMA_ID.to_string(),
                fields: Vec::new(),
            },
            envelope_violation: None,
        });
    }
    let schema =
        SchemaRegistry::get(canonical_schema_id).ok_or(EvidenceOSError::InvalidArgument)?;
    let parsed: Value =
        serde_json::from_slice(payload).map_err(|_| EvidenceOSError::InvalidArgument)?;
    reject_floats_and_depth(&parsed, 0)?;
    let obj = parsed.as_object().ok_or(EvidenceOSError::InvalidArgument)?;
    for key in obj.keys() {
        if !schema.fields.iter().any(|f| f.name == key) {
            return Err(EvidenceOSError::InvalidArgument);
        }
    }

    let mut fields = Vec::new();
    for def in &schema.fields {
        match obj.get(def.name) {
            Some(v) => fields.push(to_field(&def.kind, def.name, v)?),
            None if def.required => return Err(EvidenceOSError::InvalidArgument),
            None => {}
        }
    }
    fields.sort_by(|a, b| a.name.cmp(&b.name));
    let claim = StructuredClaim {
        schema_id: schema.id.to_string(),
        fields,
    };
    let canonical_bytes = canonical_encode(&claim)?;
    if canonical_bytes.len() > schema.max_total_bytes {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let envelope_registry = EnvelopeRegistry::with_defaults();
    let envelope_violation = envelope_registry.validate_claim(&claim).err().map(|v| *v);
    Ok(StructuredClaimValidation {
        kout_bits_upper_bound: kout_bits_upper_bound(&canonical_bytes),
        max_bytes_upper_bound: schema.max_total_bytes as u32,
        canonical_bytes,
        claim,
        envelope_violation,
    })
}

pub fn kout_bits_upper_bound(canonical_bytes: &[u8]) -> u64 {
    (canonical_bytes.len() as u64).saturating_mul(8)
}

pub fn max_bytes_upper_bound() -> u32 {
    SchemaRegistry::cbrn_v1().max_total_bytes as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn valid_payload() -> Value {
        json!({
            "schema_id": SCHEMA_ID,
            "claim_id":"c-1",
            "event_time_unix":1700000000,
            "sensor_id":"sensor-1",
            "location_id":"loc-1",
            "reason_code":"ALERT",
            "confidence_bps":9950,
            "requires_review": true,
            "measurement":"12.3 mmol/L",
            "bounded_score":{"value":"99","scale":0}
        })
    }

    #[test]
    fn validates_and_canonicalizes_cbrn_sc() {
        let payload = serde_json::to_vec(&valid_payload()).expect("json");
        let first = validate_and_canonicalize(SCHEMA_ID, &payload).expect("valid");
        let second =
            validate_and_canonicalize(SCHEMA_ID, &first.canonical_bytes).expect("re-validate");
        assert_eq!(first.canonical_bytes, second.canonical_bytes);
    }

    #[test]
    fn rejects_unknown_fields() {
        let mut payload = valid_payload();
        payload["unknown"] = json!(1);
        let bytes = serde_json::to_vec(&payload).expect("json");
        assert!(validate_and_canonicalize(SCHEMA_ID, &bytes).is_err());
    }

    #[test]
    fn rejects_dimension_mismatch() {
        let mut payload = valid_payload();
        payload["measurement"] = json!("1 s");
        let bytes = serde_json::to_vec(&payload).expect("json");
        assert!(validate_and_canonicalize(SCHEMA_ID, &bytes).is_err());
    }

    #[test]
    fn envelope_violation_is_reported() {
        let mut payload = valid_payload();
        payload["measurement"] = json!("1000001 mmol/L");
        let bytes = serde_json::to_vec(&payload).expect("json");
        let validated = validate_and_canonicalize(SCHEMA_ID, &bytes).expect("valid schema");
        assert!(validated.envelope_violation.is_some());
    }

    #[test]
    fn envelope_in_range_is_none() {
        let payload = serde_json::to_vec(&valid_payload()).expect("json");
        let validated = validate_and_canonicalize(SCHEMA_ID, &payload).expect("valid schema");
        assert!(validated.envelope_violation.is_none());
    }

    #[test]
    fn max_bytes_boundary() {
        let mut payload = valid_payload();
        payload["claim_id"] = json!("c".repeat(64));
        let bytes = serde_json::to_vec(&payload).expect("json");
        assert!(validate_and_canonicalize(SCHEMA_ID, &bytes).is_ok());
    }

    proptest! {
        #[test]
        fn canonical_deterministic_random_quantity(v in -100000i64..100000i64, scale in 0i32..4i32) {
            let mut payload = valid_payload();
            payload["measurement"] = json!(format!("{}.{} mmol/L", v, "0".repeat(scale as usize)));
            let bytes = serde_json::to_vec(&payload).expect("json");
            if let Ok(first) = validate_and_canonicalize(SCHEMA_ID, &bytes) {
                let second = validate_and_canonicalize(SCHEMA_ID, &first.canonical_bytes).expect("revalidate");
                prop_assert_eq!(first.canonical_bytes, second.canonical_bytes);
            }
        }

        #[test]
        fn random_json_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let _ = validate_and_canonicalize(SCHEMA_ID, &data);
        }
    }
}
