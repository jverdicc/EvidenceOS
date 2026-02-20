// Copyright [2026] [Joseph Verdicchio]
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
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
pub mod canary;
pub mod capsule;
pub mod crypto_transcripts;
pub mod dlc;
pub mod eprocess;
pub mod error;
pub mod etl;
pub mod ledger;
pub mod nullspec;
pub mod nullspec_contract;
pub mod nullspec_registry;
pub mod nullspec_store;
pub mod oracle;
pub mod oracle_bundle;
pub mod oracle_plusplus;
pub mod oracle_registry;
pub mod oracle_wasm;
pub mod physhir;
pub mod pln;
pub mod settlement;
pub mod structured_claims;
pub mod tee;
pub mod topicid;

pub use crate::error::{EvidenceOSError, EvidenceOSResult};

pub use crate::oracle::{OracleResolution, TieBreaker};
