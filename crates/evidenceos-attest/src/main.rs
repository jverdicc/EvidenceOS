use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use evidenceos_core::capsule::ClaimCapsule;

#[derive(Parser)]
#[command(name = "evidenceos-attest", about = "EvidenceOS attestation verifier")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Verify {
        #[arg(long)]
        capsule: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify { capsule } => verify_capsule(&capsule),
    }
}

fn verify_capsule(path: &PathBuf) -> Result<()> {
    let bytes =
        fs::read(path).with_context(|| format!("failed to read capsule: {}", path.display()))?;
    let capsule: ClaimCapsule = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to decode capsule: {}", path.display()))?;
    let att = &capsule.environment_attestations;
    let backend = att
        .tee_backend_name
        .as_deref()
        .ok_or_else(|| anyhow!("capsule missing environment_attestations.tee_backend_name"))?;
    let measurement = att
        .tee_measurement_hex
        .as_deref()
        .ok_or_else(|| anyhow!("capsule missing environment_attestations.tee_measurement_hex"))?;
    let blob_b64 = att.tee_attestation_blob_b64.as_deref().ok_or_else(|| {
        anyhow!("capsule missing environment_attestations.tee_attestation_blob_b64")
    })?;
    if measurement.len() != 64 || !measurement.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(anyhow!("invalid tee measurement hex"));
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(blob_b64)
        .map_err(|_| anyhow!("invalid attestation blob base64"))?;
    if blob.is_empty() {
        return Err(anyhow!("attestation blob must be non-empty"));
    }

    println!(
        "verified capsule attestation backend={backend} measurement={measurement} blob_len={} bytes",
        blob.len()
    );
    Ok(())
}
