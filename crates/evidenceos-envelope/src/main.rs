use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use evidenceos_core::magnitude_envelope::{EnvelopePack, TrustedEnvelopeAuthorities};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "evidenceos-envelope")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Sign {
        #[arg(long)]
        r#in: PathBuf,
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    Verify {
        #[arg(long)]
        pack: PathBuf,
        #[arg(long)]
        trusted_keys: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Sign { r#in, key, out } => {
            let bytes = std::fs::read(&r#in)?;
            let mut pack: EnvelopePack = serde_json::from_slice(&bytes)?;
            let key_hex = std::fs::read_to_string(&key)?;
            let key_raw = hex::decode(key_hex.trim())?;
            let signing = SigningKey::from_bytes(
                key_raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| "issuer.key must be 32-byte hex")?,
            );
            pack.sign_with_key(&signing)?;
            std::fs::write(out, serde_json::to_vec_pretty(&pack)?)?;
        }
        Commands::Verify { pack, trusted_keys } => {
            let bytes = std::fs::read(&pack)?;
            let pack: EnvelopePack = serde_json::from_slice(&bytes)?;
            let trusted = TrustedEnvelopeAuthorities::load_from_json(&trusted_keys)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "clock before unix epoch")?
                .as_secs();
            pack.verify_signature(&trusted, now, true)?;
        }
    }
    Ok(())
}
