use crate::error::{EvidenceOSError, EvidenceOSResult};
use crate::structured_claims::StructuredClaim;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

type AtomSpec = (Dimension, i32, Vec<(&'static str, i8)>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dimension {
    pub l: i8,
    pub m: i8,
    pub t: i8,
    pub i: i8,
    pub theta: i8,
    pub n: i8,
    pub j: i8,
}

impl Dimension {
    pub const ZERO: Self = Self::new(0, 0, 0, 0, 0, 0, 0);

    pub const fn new(l: i8, m: i8, t: i8, i: i8, theta: i8, n: i8, j: i8) -> Self {
        Self {
            l,
            m,
            t,
            i,
            theta,
            n,
            j,
        }
    }

    fn checked_add_scaled(self, rhs: Self, scale: i8) -> EvidenceOSResult<Self> {
        fn c(a: i8, b: i8) -> EvidenceOSResult<i8> {
            a.checked_add(b).ok_or(EvidenceOSError::InvalidArgument)
        }
        Ok(Self {
            l: c(self.l, rhs.l.saturating_mul(scale))?,
            m: c(self.m, rhs.m.saturating_mul(scale))?,
            t: c(self.t, rhs.t.saturating_mul(scale))?,
            i: c(self.i, rhs.i.saturating_mul(scale))?,
            theta: c(self.theta, rhs.theta.saturating_mul(scale))?,
            n: c(self.n, rhs.n.saturating_mul(scale))?,
            j: c(self.j, rhs.j.saturating_mul(scale))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unit {
    canonical: String,
    dimension: Dimension,
    factor10: i32,
}

impl Unit {
    pub fn canonical(&self) -> &str {
        &self.canonical
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quantity {
    pub value: i128,
    pub scale: i32,
    pub unit: Unit,
}

fn split_quantity(input: &str) -> EvidenceOSResult<(&str, &str)> {
    let trimmed = input.trim();
    let idx = trimmed
        .find(char::is_whitespace)
        .ok_or(EvidenceOSError::InvalidArgument)?;
    let (num, unit) = trimmed.split_at(idx);
    let unit = unit.trim();
    if num.is_empty() || unit.is_empty() {
        return Err(EvidenceOSError::InvalidArgument);
    }
    Ok((num, unit))
}

fn parse_fixed_point(num: &str) -> EvidenceOSResult<(i128, i32)> {
    let negative = num.starts_with('-');
    let digits = if negative || num.starts_with('+') {
        &num[1..]
    } else {
        num
    };
    if digits.is_empty() {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let mut parts = digits.split('.');
    let int_part = parts.next().ok_or(EvidenceOSError::InvalidArgument)?;
    let frac_part = parts.next();
    if parts.next().is_some() {
        return Err(EvidenceOSError::InvalidArgument);
    }
    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let frac = frac_part.unwrap_or("");
    if !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let combined = format!("{}{}", int_part, frac);
    let mut value = combined
        .parse::<i128>()
        .map_err(|_| EvidenceOSError::InvalidArgument)?;
    if negative {
        value = value
            .checked_neg()
            .ok_or(EvidenceOSError::InvalidArgument)?;
    }
    Ok((value, frac.len() as i32))
}

fn prefix_pow10(prefix: &str) -> Option<i32> {
    match prefix {
        "Y" => Some(24),
        "Z" => Some(21),
        "E" => Some(18),
        "P" => Some(15),
        "T" => Some(12),
        "G" => Some(9),
        "M" => Some(6),
        "k" => Some(3),
        "h" => Some(2),
        "da" => Some(1),
        "d" => Some(-1),
        "c" => Some(-2),
        "m" => Some(-3),
        "u" | "µ" => Some(-6),
        "n" => Some(-9),
        "p" => Some(-12),
        "f" => Some(-15),
        "a" => Some(-18),
        "z" => Some(-21),
        "y" => Some(-24),
        _ => None,
    }
}

fn atom_for_symbol(symbol: &str) -> Option<AtomSpec> {
    match symbol {
        "1" => Some((Dimension::ZERO, 0, vec![])),
        "m" => Some((Dimension::new(1, 0, 0, 0, 0, 0, 0), 0, vec![("m", 1)])),
        "kg" => Some((Dimension::new(0, 1, 0, 0, 0, 0, 0), 0, vec![("kg", 1)])),
        "g" => Some((Dimension::new(0, 1, 0, 0, 0, 0, 0), -3, vec![("kg", 1)])),
        "s" => Some((Dimension::new(0, 0, 1, 0, 0, 0, 0), 0, vec![("s", 1)])),
        "A" => Some((Dimension::new(0, 0, 0, 1, 0, 0, 0), 0, vec![("A", 1)])),
        "K" => Some((Dimension::new(0, 0, 0, 0, 1, 0, 0), 0, vec![("K", 1)])),
        "mol" => Some((Dimension::new(0, 0, 0, 0, 0, 1, 0), 0, vec![("mol", 1)])),
        "cd" => Some((Dimension::new(0, 0, 0, 0, 0, 0, 1), 0, vec![("cd", 1)])),
        "L" | "l" => Some((Dimension::new(3, 0, 0, 0, 0, 0, 0), -3, vec![("m", 3)])),
        "Hz" => Some((Dimension::new(0, 0, -1, 0, 0, 0, 0), 0, vec![("s", -1)])),
        "N" => Some((
            Dimension::new(1, 1, -2, 0, 0, 0, 0),
            0,
            vec![("kg", 1), ("m", 1), ("s", -2)],
        )),
        "Pa" => Some((
            Dimension::new(-1, 1, -2, 0, 0, 0, 0),
            0,
            vec![("kg", 1), ("m", -1), ("s", -2)],
        )),
        "J" => Some((
            Dimension::new(2, 1, -2, 0, 0, 0, 0),
            0,
            vec![("kg", 1), ("m", 2), ("s", -2)],
        )),
        "ppm" => Some((Dimension::ZERO, -6, vec![])),
        "ppb" => Some((Dimension::ZERO, -9, vec![])),
        _ => None,
    }
}

fn apply_atom(
    symbol: &str,
    exp: i8,
    dim: &mut Dimension,
    factor10: &mut i32,
    terms: &mut BTreeMap<&'static str, i8>,
) -> EvidenceOSResult<()> {
    let mut resolved = atom_for_symbol(symbol);
    if resolved.is_none() {
        for p in [
            "da", "Y", "Z", "E", "P", "T", "G", "M", "k", "h", "d", "c", "m", "u", "µ", "n", "p",
            "f", "a", "z", "y",
        ] {
            if let Some(base) = symbol.strip_prefix(p) {
                if let Some((d, f, t)) = atom_for_symbol(base) {
                    let pf = prefix_pow10(p).ok_or(EvidenceOSError::InvalidArgument)?;
                    resolved = Some((d, f.saturating_add(pf), t));
                    break;
                }
            }
        }
    }
    let (d, f, t) = resolved.ok_or(EvidenceOSError::InvalidArgument)?;
    *dim = dim.checked_add_scaled(d, exp)?;
    *factor10 = factor10
        .checked_add(
            f.checked_mul(i32::from(exp))
                .ok_or(EvidenceOSError::InvalidArgument)?,
        )
        .ok_or(EvidenceOSError::InvalidArgument)?;
    for (term, p) in t {
        let entry = terms.entry(term).or_insert(0);
        *entry = entry
            .checked_add(p.saturating_mul(exp))
            .ok_or(EvidenceOSError::InvalidArgument)?;
        if *entry == 0 {
            terms.remove(term);
        }
    }
    Ok(())
}

pub fn parse_unit(unit: &str) -> EvidenceOSResult<Unit> {
    let trimmed = unit.trim();
    if trimmed.is_empty() {
        return Err(EvidenceOSError::InvalidArgument);
    }
    let mut dim = Dimension::ZERO;
    let mut factor10 = 0i32;
    let mut terms = BTreeMap::new();

    let mut sign: i8 = 1;
    let mut token = String::new();
    for c in trimmed.chars().chain(['/']) {
        if c == '*' || c == '/' {
            if token.is_empty() {
                return Err(EvidenceOSError::InvalidArgument);
            }
            let mut split = token.split('^');
            let sym = split.next().ok_or(EvidenceOSError::InvalidArgument)?;
            let exp = if let Some(raw) = split.next() {
                if split.next().is_some() {
                    return Err(EvidenceOSError::InvalidArgument);
                }
                raw.parse::<i8>()
                    .map_err(|_| EvidenceOSError::InvalidArgument)?
            } else {
                1
            };
            if exp == 0 {
                return Err(EvidenceOSError::InvalidArgument);
            }
            apply_atom(
                sym,
                sign.checked_mul(exp)
                    .ok_or(EvidenceOSError::InvalidArgument)?,
                &mut dim,
                &mut factor10,
                &mut terms,
            )?;
            token.clear();
            sign = if c == '/' { -1 } else { 1 };
        } else if !c.is_whitespace() {
            token.push(c);
        }
    }

    let mut numerator = Vec::new();
    let mut denominator = Vec::new();
    for (sym, exp) in &terms {
        if *exp > 0 {
            numerator.push((sym.to_string(), *exp));
        } else {
            denominator.push((sym.to_string(), exp.saturating_neg()));
        }
    }
    let fmt = |(s, e): (String, i8)| {
        if e == 1 {
            s
        } else {
            format!("{s}^{e}")
        }
    };
    let num = if numerator.is_empty() {
        "1".to_string()
    } else {
        numerator.into_iter().map(fmt).collect::<Vec<_>>().join("*")
    };
    let canonical = if denominator.is_empty() {
        num
    } else {
        format!(
            "{num}/{}",
            denominator
                .into_iter()
                .map(fmt)
                .collect::<Vec<_>>()
                .join("*")
        )
    };

    Ok(Unit {
        canonical,
        dimension: dim,
        factor10,
    })
}

pub fn quantity_from_parts(value: i128, scale: i32, unit: &str) -> EvidenceOSResult<Quantity> {
    let unit = parse_unit(unit)?;
    Ok(Quantity { value, scale, unit })
}

pub fn parse_quantity(input: &str) -> EvidenceOSResult<Quantity> {
    let (n, u) = split_quantity(input)?;
    let (value, scale) = parse_fixed_point(n)?;
    let unit = parse_unit(u)?;
    let normalized_scale = scale
        .checked_sub(unit.factor10)
        .ok_or(EvidenceOSError::InvalidArgument)?;
    Ok(Quantity {
        value,
        scale: normalized_scale,
        unit: Unit {
            canonical: unit.canonical,
            dimension: unit.dimension,
            factor10: 0,
        },
    })
}

pub fn dimension_of(unit: &Unit) -> Dimension {
    unit.dimension
}

pub fn check_dimension(quantity: &Quantity, expected_dimension: Dimension) -> EvidenceOSResult<()> {
    if dimension_of(&quantity.unit) != expected_dimension {
        return Err(EvidenceOSError::InvalidArgument);
    }
    Ok(())
}

pub fn physhir_signature_hash(claim: &StructuredClaim) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(claim.schema_id.as_bytes());
    for field in &claim.fields {
        hasher.update(field.name.as_bytes());
        hasher.update([field.value.tag()]);
        hasher.update(field.value.canonical_bytes());
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_si_with_prefixes() {
        let q = parse_quantity("12.3 mmol/L").expect("parse");
        assert_eq!(q.value, 123);
        assert_eq!(q.scale, 1);
        assert_eq!(q.unit.canonical(), "mol/m^3");
        assert_eq!(dimension_of(&q.unit), Dimension::new(-3, 0, 0, 0, 0, 1, 0));
    }

    #[test]
    fn dimension_mismatch_rejected() {
        let q = parse_quantity("5 s").expect("parse");
        assert!(check_dimension(&q, Dimension::new(1, 0, 0, 0, 0, 0, 0)).is_err());
    }
}
