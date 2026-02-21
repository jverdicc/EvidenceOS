use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use evidenceos_attest::{load_policy, verify_attestation_blob};
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
        #[arg(long)]
        policy: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify { capsule, policy } => verify_capsule(&capsule, &policy),
    }
}

fn verify_capsule(capsule_path: &PathBuf, policy_path: &PathBuf) -> Result<()> {
    let bytes = fs::read(capsule_path)
        .with_context(|| format!("failed to read capsule: {}", capsule_path.display()))?;
    let capsule: ClaimCapsule = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to decode capsule: {}", capsule_path.display()))?;
    let policy_bytes = fs::read(policy_path)
        .with_context(|| format!("failed to read policy: {}", policy_path.display()))?;
    let policy = load_policy(&policy_bytes)?;

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

    verify_attestation_blob(backend, measurement, blob_b64, &policy)?;

    println!("verified capsule attestation backend={backend} measurement={measurement}");
    Ok(())
}
