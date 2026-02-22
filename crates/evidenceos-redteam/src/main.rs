use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, ValueEnum};
use evidenceos_protocol::pb::{self, evidence_os_client::EvidenceOsClient};
use std::collections::HashSet;
use std::time::{Duration, Instant};
use tonic::{Code, Status};

const PUBLIC_ERROR_METADATA_KEY: &str = "x-evidenceos-public-error-code";
const PUBLIC_ERROR_CODES: &[&str] = &[
    "INVALID_INPUT",
    "UNAUTHORIZED",
    "FORBIDDEN",
    "NOT_FOUND",
    "FAILED_PRECONDITION",
    "RATE_LIMITED",
    "RESOURCE_EXHAUSTED",
    "INTERNAL",
    "UNAVAILABLE",
    "DEADLINE_EXCEEDED",
];

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    endpoint: String,
    #[arg(long, value_enum, default_value_t = SuiteMode::Evidenceos)]
    mode: SuiteMode,
    #[arg(long, default_value_t = 20)]
    timing_samples: usize,
    #[arg(long, default_value_t = 0.55)]
    max_auc: f64,
    #[arg(long, default_value_t = 16)]
    max_size_variance_bytes: usize,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum SuiteMode {
    Evidenceos,
    DiscosSubset,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let mut client = EvidenceOsClient::connect(args.endpoint.clone())
        .await
        .with_context(|| format!("connect failed: {}", args.endpoint))?;

    let health = client.health(pb::HealthRequest {}).await;
    if health.is_err() {
        bail!("daemon health probe failed");
    }

    let mut failures = Vec::new();

    if let Err(err) = timing_probe_adversary(&mut client, args.timing_samples, args.max_auc).await {
        failures.push(format!("TimingProbeAdversary: {err}"));
    }

    if let Err(err) = error_probe_adversary(&mut client).await {
        failures.push(format!("ErrorProbeAdversary: {err}"));
    }

    if let Err(err) = output_size_probe_adversary(&mut client, args.max_size_variance_bytes).await {
        failures.push(format!("OutputSizeProbeAdversary: {err}"));
    }

    if matches!(args.mode, SuiteMode::Evidenceos) {
        if let Err(err) = topic_sybil_adversary(&mut client).await {
            failures.push(format!("TopicSybilAdversary: {err}"));
        }
        if let Err(err) = nullspec_swap_adversary(&mut client).await {
            failures.push(format!("NullSpecSwapAdversary: {err}"));
        }
    }

    if failures.is_empty() {
        println!("red-team suite passed");
        return Ok(());
    }

    for failure in &failures {
        eprintln!("[redteam-fail] {failure}");
    }
    bail!("red-team suite failed with {} issue(s)", failures.len())
}

async fn timing_probe_adversary(
    client: &mut EvidenceOsClient<tonic::transport::Channel>,
    samples: usize,
    max_auc: f64,
) -> Result<()> {
    let mut class_a = Vec::with_capacity(samples);
    let mut class_b = Vec::with_capacity(samples);

    for i in 0..samples {
        class_a.push(timed_create_claim(client, &format!("arm-a-{i}"), "budget-a").await?);
        class_b.push(timed_create_claim(client, &format!("arm-b-{i}"), "budget-b").await?);
    }

    let auc = auc(&class_a, &class_b);
    if auc > max_auc {
        bail!("AUC {:.3} exceeded threshold {:.3}", auc, max_auc);
    }
    Ok(())
}

async fn timed_create_claim(
    client: &mut EvidenceOsClient<tonic::transport::Channel>,
    claim_name: &str,
    holdout_ref: &str,
) -> Result<Duration> {
    let req = create_claim_request(claim_name, holdout_ref, "");
    let start = Instant::now();
    let res = client.create_claim_v2(req).await;
    let elapsed = start.elapsed();
    let status = res.expect_err("expected failure");
    assert_public_error_code(&status)?;
    Ok(elapsed)
}

fn auc(a: &[Duration], b: &[Duration]) -> f64 {
    let mut wins = 0.0;
    for va in a {
        for vb in b {
            if va > vb {
                wins += 1.0;
            } else if va == vb {
                wins += 0.5;
            }
        }
    }
    wins / ((a.len() * b.len()) as f64)
}

async fn error_probe_adversary(
    client: &mut EvidenceOsClient<tonic::transport::Channel>,
) -> Result<()> {
    let probes = [
        create_claim_request("bad-enum", "holdout", "nope"),
        create_claim_request("bad-len", "", ""),
        pb::CreateClaimV2Request {
            claim_name: String::new(),
            metadata: None,
            signals: None,
            holdout_ref: String::new(),
            epoch_size: 0,
            oracle_num_symbols: 1,
            access_credit: 0,
            oracle_id: String::new(),
            nullspec_id: String::new(),
            dp_epsilon_budget: None,
            dp_delta_budget: None,
        },
    ];

    for probe in probes {
        let status = client
            .create_claim_v2(probe)
            .await
            .expect_err("expected malformed request to fail");
        assert_public_error_code(&status)?;
    }

    Ok(())
}

async fn output_size_probe_adversary(
    client: &mut EvidenceOsClient<tonic::transport::Channel>,
    max_size_variance_bytes: usize,
) -> Result<()> {
    let mut sizes = Vec::new();
    for len in [1usize, 8, 32, 64] {
        let mut req = create_claim_request("size-probe", "holdout", "");
        req.claim_name = "x".repeat(len);
        let status = client
            .create_claim_v2(req)
            .await
            .expect_err("expected failure");
        assert_public_error_code(&status)?;
        sizes.push(serialized_error_len(&status));
    }
    let min = *sizes.iter().min().ok_or_else(|| anyhow!("no sizes"))?;
    let max = *sizes.iter().max().ok_or_else(|| anyhow!("no sizes"))?;
    if max.saturating_sub(min) > max_size_variance_bytes {
        bail!(
            "response size variance {} exceeded threshold {}",
            max - min,
            max_size_variance_bytes
        );
    }
    Ok(())
}

async fn topic_sybil_adversary(
    client: &mut EvidenceOsClient<tonic::transport::Channel>,
) -> Result<()> {
    let mut seen_codes = HashSet::new();
    for i in 0..10 {
        let req = create_claim_request(&format!("sybil-{i}"), &format!("holdout-{i}"), "");
        let status = client
            .create_claim_v2(req)
            .await
            .expect_err("expected sybil probe to fail");
        assert_public_error_code(&status)?;
        seen_codes.insert(status.code());
    }
    if seen_codes.contains(&Code::Ok) {
        bail!("topic sybil probe unexpectedly succeeded");
    }
    Ok(())
}

async fn nullspec_swap_adversary(
    client: &mut EvidenceOsClient<tonic::transport::Channel>,
) -> Result<()> {
    let req = create_claim_request(
        "nullspec-swap",
        "holdout-a",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
    let status = client
        .create_claim_v2(req)
        .await
        .expect_err("expected unsigned/unknown nullspec to fail");
    assert_public_error_code(&status)?;
    if !matches!(
        status.code(),
        Code::FailedPrecondition | Code::InvalidArgument | Code::PermissionDenied
    ) {
        bail!(
            "unexpected status code for nullspec swap: {}",
            status.code()
        );
    }
    Ok(())
}

fn assert_public_error_code(status: &Status) -> Result<()> {
    let code = status
        .metadata()
        .get(PUBLIC_ERROR_METADATA_KEY)
        .ok_or_else(|| anyhow!("missing public error code metadata"))?
        .to_str()
        .context("invalid public error code metadata")?;
    if !PUBLIC_ERROR_CODES.contains(&code) {
        bail!("unknown public error code: {code}");
    }
    Ok(())
}

fn serialized_error_len(status: &Status) -> usize {
    let meta_len: usize = status
        .metadata()
        .iter()
        .map(|kv| kv.0.as_str().len() + kv.1.as_encoded_bytes().len())
        .sum();
    status.message().len() + meta_len + status.code().to_string().len()
}

fn create_claim_request(
    claim_name: &str,
    holdout_ref: &str,
    nullspec_id: &str,
) -> pb::CreateClaimV2Request {
    pb::CreateClaimV2Request {
        claim_name: claim_name.to_string(),
        metadata: Some(pb::ClaimMetadataV2 {
            lane: "fast".to_string(),
            alpha_micros: 50_000,
            epoch_config_ref: "epoch-a".to_string(),
            output_schema_id: "legacy/v1".to_string(),
        }),
        signals: Some(pb::TopicSignalsV2 {
            semantic_hash: vec![1; 32],
            phys_hir_signature_hash: vec![2; 32],
            dependency_merkle_root: vec![3; 32],
        }),
        holdout_ref: holdout_ref.to_string(),
        epoch_size: 10,
        oracle_num_symbols: 4,
        access_credit: 64,
        oracle_id: "builtin.accuracy".to_string(),
        nullspec_id: nullspec_id.to_string(),
        dp_epsilon_budget: None,
        dp_delta_budget: None,
    }
}
