use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::magnitude_envelope::{EnvelopeRegistry, EnvelopeViolation};
use crate::physhir::{check_dimension, quantity_from_parts, Dimension, Quantity};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub const EVIDENCEOS_SC_V0: &str = "EVIDENCEOS_SC_V0";
pub const EVIDENCEOS_CBRN_SC_V1: &str = "EVIDENCEOS_CBRN_SC_V1";
pub const LEGACY_SCHEMA_ID: &str = EVIDENCEOS_SC_V0;
pub const SCHEMA_ID: &str = EVIDENCEOS_CBRN_SC_V1;
pub const SCHEMA_ID_ALIAS: &str = "cbrn-sc.v1";
const MAX_DEPTH: usize = 6;
const MAX_QUANTITIES: usize = 8;
const MAX_REFERENCES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalFieldValue {
    Enum(String),
    Bool(bool),
    Int(i64),
    FixedPoint { value: i128, scale: i32 },
    Quantity(Quantity),
    Bytes(String),
    QuantityList(Vec<CanonicalQuantityEntry>),
    IdList(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalQuantityEntry {
    pub kind: String,
    pub quantity: Quantity,
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
            Self::QuantityList(_) => 7,
            Self::IdList(_) => 8,
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
            Self::QuantityList(items) => items
                .iter()
                .flat_map(|q| {
                    format!(
                        "{}:{}@{}:{};",
                        q.kind,
                        q.quantity.value,
                        q.quantity.scale,
                        q.quantity.unit.canonical()
                    )
                    .into_bytes()
                })
                .collect(),
            Self::IdList(ids) => ids.join(";").into_bytes(),
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

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum DomainV1 {
    Chemical,
    Biological,
    Radiological,
    Nuclear,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ClaimKindV1 {
    Measurement,
    Detection,
    Clearance,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum UnitSystemV1 {
    PhyshirUcumSubset,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum EnvelopeCheckV1 {
    Pass,
    Fail,
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum QuantityKindV1 {
    Concentration,
    DoseRate,
    Temperature,
    Pressure,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FixedPointV1 {
    value: String,
    scale: i32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuantityV1 {
    kind: QuantityKindV1,
    value: FixedPointV1,
    unit: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CbrnClaimV1 {
    schema_id: Option<String>,
    version: u8,
    profile: String,
    domain: DomainV1,
    claim_kind: ClaimKindV1,
    claim_id: String,
    sensor_id: String,
    event_time_unix: u64,
    quantities: Vec<QuantityV1>,
    unit_system: UnitSystemV1,
    envelope_id: String,
    envelope_check: EnvelopeCheckV1,
    references: Vec<String>,
}

pub fn canonicalize_schema_id(output_schema_id: &str) -> EvidenceOSResult<&'static str> {
    if [LEGACY_SCHEMA_ID, "legacy/v1", "EVIDENCEOS_SC_V0"].contains(&output_schema_id) {
        return Ok(LEGACY_SCHEMA_ID);
    }
    if [
        SCHEMA_ID,
        SCHEMA_ID_ALIAS,
        "cbrn/v1",
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

fn is_hex_id(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_base32_id(s: &str) -> bool {
    (8..=52).contains(&s.len()) && s.chars().all(|c| matches!(c, 'A'..='Z' | '2'..='7'))
}

fn is_valid_id(s: &str) -> bool {
    is_hex_id(s) || is_base32_id(s)
}

fn parse_fixed_point(v: &FixedPointV1) -> EvidenceOSResult<(i128, i32)> {
    let value = v
        .value
        .parse::<i128>()
        .map_err(|_| EvidenceOSError::InvalidArgument)?;
    Ok((value, v.scale))
}

fn parse_quantity_v1(input: &QuantityV1) -> EvidenceOSResult<CanonicalQuantityEntry> {
    let (value, scale) = parse_fixed_point(&input.value)?;
    if !(-12..=12).contains(&scale)
        || !(-1_000_000_000_000i128..=1_000_000_000_000i128).contains(&value)
    {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let (expected_dimension, allowed_units, kind_str) = match input.kind {
        QuantityKindV1::Concentration => (
            Dimension::new(-3, 0, 0, 0, 0, 1, 0),
            ["mol/m^3", "mmol/L", "ppm", "ppb"].as_slice(),
            "CONCENTRATION",
        ),
        QuantityKindV1::DoseRate => (
            Dimension::new(0, 2, -3, 0, 0, 0, 0),
            ["Sv/h"].as_slice(),
            "DOSE_RATE",
        ),
        QuantityKindV1::Temperature => (
            Dimension::new(0, 0, 0, 0, 1, 0, 0),
            ["K"].as_slice(),
            "TEMPERATURE",
        ),
        QuantityKindV1::Pressure => (
            Dimension::new(-1, 1, -2, 0, 0, 0, 0),
            ["Pa", "kPa"].as_slice(),
            "PRESSURE",
        ),
    };
    if !allowed_units.contains(&input.unit.as_str()) {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let quantity = quantity_from_parts(value, scale, &input.unit)?;
    check_dimension(&quantity, expected_dimension)?;
    Ok(CanonicalQuantityEntry {
        kind: kind_str.to_string(),
        quantity,
    })
}

fn claim_from_v1(v1: CbrnClaimV1) -> EvidenceOSResult<StructuredClaim> {
    if v1.schema_id.as_deref().is_some_and(|v| v != SCHEMA_ID)
        || v1.version != 1
        || v1.profile != "CBRN_SC_V1"
        || !is_valid_id(&v1.claim_id)
        || !is_valid_id(&v1.sensor_id)
    {
        return Err(EvidenceOSError::InvalidArgument);
    }
    if v1.event_time_unix > 4_102_444_800
        || v1.quantities.is_empty()
        || v1.quantities.len() > MAX_QUANTITIES
    {
        return Err(EvidenceOSError::InvalidArgument);
    }
    if !is_hex_id(&v1.envelope_id) || v1.references.len() > MAX_REFERENCES {
        return Err(EvidenceOSError::InvalidArgument);
    }
    if !v1.references.iter().all(|r| is_valid_id(r)) {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let quantities = v1
        .quantities
        .iter()
        .map(parse_quantity_v1)
        .collect::<EvidenceOSResult<Vec<_>>>()?;
    let mut fields = vec![
        StructuredField {
            name: "version".to_string(),
            value: CanonicalFieldValue::Int(1),
        },
        StructuredField {
            name: "profile".to_string(),
            value: CanonicalFieldValue::Enum("CBRN_SC_V1".to_string()),
        },
        StructuredField {
            name: "domain".to_string(),
            value: CanonicalFieldValue::Enum(format!("{:?}", v1.domain).to_uppercase()),
        },
        StructuredField {
            name: "claim_kind".to_string(),
            value: CanonicalFieldValue::Enum(format!("{:?}", v1.claim_kind).to_uppercase()),
        },
        StructuredField {
            name: "claim_id".to_string(),
            value: CanonicalFieldValue::Bytes(v1.claim_id),
        },
        StructuredField {
            name: "sensor_id".to_string(),
            value: CanonicalFieldValue::Bytes(v1.sensor_id),
        },
        StructuredField {
            name: "event_time_unix".to_string(),
            value: CanonicalFieldValue::Int(
                i64::try_from(v1.event_time_unix).map_err(|_| EvidenceOSError::InvalidArgument)?,
            ),
        },
        StructuredField {
            name: "quantities".to_string(),
            value: CanonicalFieldValue::QuantityList(quantities),
        },
        StructuredField {
            name: "unit_system".to_string(),
            value: CanonicalFieldValue::Enum(match v1.unit_system {
                UnitSystemV1::PhyshirUcumSubset => "PHYSHIR_UCUM_SUBSET".to_string(),
            }),
        },
        StructuredField {
            name: "envelope_id".to_string(),
            value: CanonicalFieldValue::Bytes(v1.envelope_id),
        },
        StructuredField {
            name: "envelope_check".to_string(),
            value: CanonicalFieldValue::Enum(
                match v1.envelope_check {
                    EnvelopeCheckV1::Pass => "PASS",
                    EnvelopeCheckV1::Fail => "FAIL",
                    EnvelopeCheckV1::Unknown => "UNKNOWN",
                }
                .to_string(),
            ),
        },
        StructuredField {
            name: "references".to_string(),
            value: CanonicalFieldValue::IdList(v1.references),
        },
    ];
    fields.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(StructuredClaim {
        schema_id: SCHEMA_ID.to_string(),
        fields,
    })
}

fn sort_json(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut entries: Vec<(String, Value)> = map.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            let mut sorted = Map::new();
            for (k, val) in entries {
                sorted.insert(k, sort_json(val));
            }
            Value::Object(sorted)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_json).collect()),
        other => other,
    }
}

pub fn canonical_encode(claim: &StructuredClaim) -> EvidenceOSResult<Vec<u8>> {
    let mut out = Map::new();
    out.insert(
        "schema_id".to_string(),
        Value::String(claim.schema_id.clone()),
    );
    for field in &claim.fields {
        let value = match &field.value {
            CanonicalFieldValue::Enum(v) | CanonicalFieldValue::Bytes(v) => Value::String(v.clone()),
            CanonicalFieldValue::Bool(v) => Value::Bool(*v),
            CanonicalFieldValue::Int(v) => Value::Number((*v).into()),
            CanonicalFieldValue::FixedPoint { value, scale } => {
                serde_json::json!({"scale": scale, "value": value.to_string()})
            }
            CanonicalFieldValue::Quantity(q) => {
                serde_json::json!({"scale": q.scale, "unit": q.unit.canonical(), "value": q.value.to_string()})
            }
            CanonicalFieldValue::QuantityList(list) => Value::Array(list.iter().map(|q| {
                serde_json::json!({"kind": q.kind, "unit": q.quantity.unit.canonical(), "value": {"value": q.quantity.value.to_string(), "scale": q.quantity.scale}})
            }).collect()),
            CanonicalFieldValue::IdList(list) => Value::Array(list.iter().map(|s| Value::String(s.clone())).collect()),
        };
        out.insert(field.name.clone(), value);
    }
    serde_json::to_vec(&sort_json(Value::Object(out))).map_err(|_| EvidenceOSError::Internal)
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
    let parsed: Value =
        serde_json::from_slice(payload).map_err(|_| EvidenceOSError::InvalidArgument)?;
    reject_floats_and_depth(&parsed, 0)?;
    let typed: CbrnClaimV1 =
        serde_json::from_value(parsed).map_err(|_| EvidenceOSError::InvalidArgument)?;
    let claim = claim_from_v1(typed)?;
    let canonical_bytes = canonical_encode(&claim)?;
    if canonical_bytes.len() > max_bytes_upper_bound() as usize {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let envelope_registry = EnvelopeRegistry::with_builtin_defaults();
    let mut envelope_violation = envelope_registry.validate_claim(&claim).err().map(|v| *v);
    if envelope_violation.is_none()
        && claim.fields.iter().any(|f| {
            f.name == "envelope_check"
                && matches!(&f.value, CanonicalFieldValue::Enum(v) if v == "FAIL")
        })
    {
        envelope_violation = Some(EnvelopeViolation {
            profile_id: "cbrn.v1".to_string(),
            schema_id: SCHEMA_ID.to_string(),
            field: "envelope_check".to_string(),
            min_value: 1,
            max_value: 1,
            observed_value: 0,
        });
    }
    Ok(StructuredClaimValidation {
        kout_bits_upper_bound: kout_bits_upper_bound_for_claim(&claim),
        max_bytes_upper_bound: max_bytes_upper_bound(),
        canonical_bytes,
        claim,
        envelope_violation,
    })
}

const fn ceil_log2_u64(mut x: u64) -> u64 {
    if x <= 1 {
        return 0;
    }
    x -= 1;
    let mut bits = 0;
    while x > 0 {
        bits += 1;
        x >>= 1;
    }
    bits
}

fn kout_bits_upper_bound_for_claim(claim: &StructuredClaim) -> u64 {
    if claim.schema_id == LEGACY_SCHEMA_ID {
        return 0;
    }
    let base = ceil_log2_u64(2)
        + ceil_log2_u64(4)
        + ceil_log2_u64(3)
        + ceil_log2_u64(4)
        + 256
        + 260
        + ceil_log2_u64(4_102_444_801)
        + ceil_log2_u64(1)
        + 256
        + ceil_log2_u64(3);
    let quantity_entry =
        ceil_log2_u64(4) + ceil_log2_u64(2_000_000_000_001) + ceil_log2_u64(25) + ceil_log2_u64(4);
    base + ceil_log2_u64((MAX_QUANTITIES + 1) as u64)
        + (MAX_QUANTITIES as u64) * quantity_entry
        + ceil_log2_u64((MAX_REFERENCES + 1) as u64)
        + (MAX_REFERENCES as u64) * 260
}

pub fn kout_bits_upper_bound(canonical_bytes: &[u8]) -> u64 {
    if canonical_bytes.is_empty() {
        0
    } else {
        kout_bits_upper_bound_for_claim(&StructuredClaim {
            schema_id: SCHEMA_ID.to_string(),
            fields: vec![],
        })
    }
}

pub fn schema_kout_bits_upper_bound(output_schema_id: &str) -> EvidenceOSResult<u64> {
    let canonical_schema_id = canonicalize_schema_id(output_schema_id)?;
    if canonical_schema_id == LEGACY_SCHEMA_ID {
        Ok(0)
    } else {
        Ok(kout_bits_upper_bound_for_claim(&StructuredClaim {
            schema_id: SCHEMA_ID.to_string(),
            fields: vec![],
        }))
    }
}

pub fn max_bytes_upper_bound() -> u32 {
    2048
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn id_hex() -> String {
        "a".repeat(64)
    }

    fn valid_payload() -> Value {
        json!({
            "version":1,
            "profile":"CBRN_SC_V1",
            "domain":"CHEMICAL",
            "claim_kind":"MEASUREMENT",
            "claim_id": id_hex(),
            "sensor_id": "ABCDEFGH234567AB",
            "event_time_unix":1700000000,
            "quantities":[{"kind":"CONCENTRATION","value":{"value":"123","scale":1},"unit":"mmol/L"}],
            "unit_system":"PHYSHIR_UCUM_SUBSET",
            "envelope_id": id_hex(),
            "envelope_check":"PASS",
            "references":[id_hex()]
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
    fn rejects_float() {
        let mut payload = valid_payload();
        payload["quantities"][0]["value"]["value"] = json!(1.2);
        let bytes = serde_json::to_vec(&payload).expect("json");
        assert!(validate_and_canonicalize(SCHEMA_ID, &bytes).is_err());
    }

    #[test]
    fn kout_bound_is_domain_based() {
        let payload = serde_json::to_vec(&valid_payload()).expect("json");
        let validated = validate_and_canonicalize(SCHEMA_ID, &payload).expect("valid schema");
        assert!(validated.kout_bits_upper_bound > (validated.canonical_bytes.len() as u64 * 2));
    }

    #[test]
    fn rejects_invalid_id_format() {
        let mut payload = valid_payload();
        payload["claim_id"] = json!("http://not-allowed");
        let bytes = serde_json::to_vec(&payload).expect("json");
        assert!(validate_and_canonicalize(SCHEMA_ID, &bytes).is_err());
    }
}
