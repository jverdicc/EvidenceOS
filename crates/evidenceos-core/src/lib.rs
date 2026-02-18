// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

//! evidenceos-core
//!
//! A reference Rust implementation of the *EvidenceOS* verification-kernel core.
//!
//! This crate implements core protocol invariants:
//! - Conservation Ledger (leakage `k`, evidence wealth `W`, certification barrier)
//! - OracleResolution + output hysteresis (anti-probing)
//! - Deterministic Logical Clock (DLC) + protocol-level PLN padding
//! - Evidence Transparency Log (ETL): append-only log + Merkle root
//! - A decidable ASPEC-like verifier for restricted WebAssembly modules

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod aspec;
pub mod capsule;
pub mod dlc;
pub mod error;
pub mod etl;
pub mod ledger;
pub mod oracle;
pub mod topicid;

pub use crate::error::{EvidenceOSError, EvidenceOSResult};

pub use crate::oracle::{OracleResolution, TieBreaker};
