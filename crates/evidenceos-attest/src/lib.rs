use std::collections::BTreeSet;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use ring::signature;
use rustls_pemfile::certs;
use rustls_pki_types::{CertificateDer, TrustAnchor, UnixTime};
use serde::Deserialize;
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};

const SNP_REPORT_SIGNED_SIZE: usize = 0x2A0;
const SNP_REPORT_DATA_OFFSET: usize = 0x50;
const SNP_REPORT_DATA_SIZE: usize = 64;
const SNP_CURRENT_TCB_OFFSET: usize = 0x180;
const SNP_SIG_R_OFFSET: usize = 0x2A0;
const SNP_SIG_S_OFFSET: usize = 0x2E8;
const SNP_SIG_COMPONENT_LEN: usize = 72;

#[derive(Debug, Deserialize)]
pub struct AttestationPolicy {
    pub allowed_measurements: Vec<String>,
    #[serde(default)]
    pub minimum_tcb: TcbVersion,
}

#[derive(Debug, Deserialize, Default)]
pub struct TcbVersion {
    #[serde(default)]
    pub boot_loader: u8,
    #[serde(default)]
    pub tee: u8,
    #[serde(default)]
    pub snp: u8,
    #[serde(default)]
    pub microcode: u8,
}

#[derive(Debug, Deserialize)]
struct SevsnpBundle {
    report_b64: String,
    vcek_pem: String,
    ask_pem: String,
    ark_pem: String,
}

pub fn load_policy(policy_json: &[u8]) -> Result<AttestationPolicy> {
    let policy: AttestationPolicy =
        serde_json::from_slice(policy_json).context("failed to parse attestation policy")?;
    if policy.allowed_measurements.is_empty() {
        return Err(anyhow!("policy.allowed_measurements must not be empty"));
    }
    for m in &policy.allowed_measurements {
        if m.len() != 64 || !m.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(anyhow!("policy allowed measurement must be 64-char hex"));
        }
    }
    Ok(policy)
}

pub fn verify_attestation_blob(
    backend: &str,
    expected_measurement_hex: &str,
    blob_b64: &str,
    policy: &AttestationPolicy,
) -> Result<()> {
    if backend != "amd-sev-snp" {
        return Err(anyhow!(
            "unsupported backend for cryptographic verification: {backend}"
        ));
    }
    if expected_measurement_hex.len() != 64
        || !expected_measurement_hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(anyhow!("invalid expected measurement hex"));
    }
    let allowed: BTreeSet<&str> = policy
        .allowed_measurements
        .iter()
        .map(String::as_str)
        .collect();
    if !allowed.contains(expected_measurement_hex) {
        return Err(anyhow!("measurement is not allowed by policy"));
    }

    let bundle_json = base64::engine::general_purpose::STANDARD
        .decode(blob_b64)
        .context("invalid attestation blob base64")?;
    let bundle: SevsnpBundle =
        serde_json::from_slice(&bundle_json).context("invalid SEV-SNP attestation bundle")?;

    verify_sevsnp_bundle(expected_measurement_hex, &bundle, policy)
}

fn verify_sevsnp_bundle(
    expected_measurement_hex: &str,
    bundle: &SevsnpBundle,
    policy: &AttestationPolicy,
) -> Result<()> {
    let report = base64::engine::general_purpose::STANDARD
        .decode(&bundle.report_b64)
        .context("invalid report_b64")?;
    if report.len() < SNP_SIG_S_OFFSET + SNP_SIG_COMPONENT_LEN {
        return Err(anyhow!("SEV-SNP report too short"));
    }

    let expected =
        hex::decode(expected_measurement_hex).map_err(|_| anyhow!("invalid measurement"))?;
    let report_data =
        &report[SNP_REPORT_DATA_OFFSET..SNP_REPORT_DATA_OFFSET + SNP_REPORT_DATA_SIZE];
    if report_data[..32] != expected {
        return Err(anyhow!("report_data does not match expected measurement"));
    }

    let current_tcb = u64::from_le_bytes(
        report[SNP_CURRENT_TCB_OFFSET..SNP_CURRENT_TCB_OFFSET + 8]
            .try_into()
            .map_err(|_| anyhow!("invalid TCB field"))?,
    );
    let boot_loader = (current_tcb & 0xff) as u8;
    let tee = ((current_tcb >> 8) & 0xff) as u8;
    let snp = ((current_tcb >> 48) & 0xff) as u8;
    let microcode = ((current_tcb >> 56) & 0xff) as u8;
    if boot_loader < policy.minimum_tcb.boot_loader
        || tee < policy.minimum_tcb.tee
        || snp < policy.minimum_tcb.snp
        || microcode < policy.minimum_tcb.microcode
    {
        return Err(anyhow!("report TCB is below policy minimums"));
    }

    let vcek_der = parse_single_pem_cert(&bundle.vcek_pem)?;
    let ask_der = parse_single_pem_cert(&bundle.ask_pem)?;
    let ark_der = parse_single_pem_cert(&bundle.ark_pem)?;
    let vcek_cert = CertificateDer::from(vcek_der.clone());
    let ark_cert = CertificateDer::from(ark_der);
    let ask_cert = CertificateDer::from(ask_der);
    let end_entity = EndEntityCert::try_from(&vcek_cert)?;
    let anchor: TrustAnchor<'_> = anchor_from_trusted_cert(&ark_cert)?;
    let intermediates = vec![ask_cert];
    let now = UnixTime::since_unix_epoch(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| anyhow!("system clock is before UNIX_EPOCH"))?,
    );
    end_entity.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &[anchor],
        &intermediates,
        now,
        KeyUsage::server_auth(),
        None,
        None,
    )?;

    let sig = report_signature_raw(&report)?;
    let signed = &report[..SNP_REPORT_SIGNED_SIZE];
    let verifier = signature::UnparsedPublicKey::new(
        &signature::ECDSA_P384_SHA384_FIXED,
        end_entity.subject_public_key_info(),
    );
    verifier
        .verify(signed, &sig)
        .map_err(|_| anyhow!("report signature verification failed"))?;

    Ok(())
}

fn parse_single_pem_cert(pem: &str) -> Result<Vec<u8>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let mut found = certs(&mut reader);
    let first = found
        .next()
        .transpose()?
        .ok_or_else(|| anyhow!("PEM cert not found"))?;
    if found.next().is_some() {
        return Err(anyhow!("expected single PEM cert"));
    }
    Ok(first.as_ref().to_vec())
}

fn report_signature_raw(report: &[u8]) -> Result<Vec<u8>> {
    let r = &report[SNP_SIG_R_OFFSET..SNP_SIG_R_OFFSET + SNP_SIG_COMPONENT_LEN];
    let s = &report[SNP_SIG_S_OFFSET..SNP_SIG_S_OFFSET + SNP_SIG_COMPONENT_LEN];
    let mut r_be = r.to_vec();
    r_be.reverse();
    let mut s_be = s.to_vec();
    s_be.reverse();
    let r_norm = trim_or_pad_48(&r_be)?;
    let s_norm = trim_or_pad_48(&s_be)?;
    Ok([r_norm, s_norm].concat())
}

fn trim_or_pad_48(mut be: &[u8]) -> Result<Vec<u8>> {
    while be.first() == Some(&0) {
        be = &be[1..];
    }
    if be.len() > 48 {
        return Err(anyhow!("signature component too large"));
    }
    let mut out = vec![0_u8; 48 - be.len()];
    out.extend_from_slice(be);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_requires_measurements() {
        let err = load_policy(br#"{"allowed_measurements":[]}"#).expect_err("must fail");
        assert!(err.to_string().contains("must not be empty"));
    }

    #[test]
    fn reject_unsupported_backend() {
        let policy = load_policy(br#"{"allowed_measurements":["0000000000000000000000000000000000000000000000000000000000000000"]}"#)
            .expect("policy");
        let err = verify_attestation_blob("noop", &policy.allowed_measurements[0], "", &policy)
            .expect_err("must fail");
        assert!(err.to_string().contains("unsupported backend"));
    }
}
