// Copyright (c) 2026 Joseph Verdicchio and EvidenceOS Contributors
// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]
#![forbid(unsafe_code)]

use core::fmt;

pub mod pb {
    tonic::include_proto!("evidenceos.v1");
}

pub type ClaimId = [u8; 32];
pub type HoldoutHandle = [u8; 32];
pub type TopicId = [u8; 32];
pub type CapsuleHash = [u8; 32];

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lane {
    Fast = 0,
    Sealed = 1,
    Heavy = 2,
    Dp = 3,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    EOk = 0,
    EAdmissionDenied = 1,
    ENoncanonical = 2,
    EBudgetExceeded = 3,
    ESystemFrozen = 4,
    ELogCollision = 5,
    ESystemDrift = 6,
    ETainted = 7,
    EStaleEpoch = 8,
    EInvalidArgument = 9,
    ENotFound = 10,
    EAspecRejected = 11,
    EInternal = 12,
    EInvalidState = 13,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalBytes<const L: usize>([u8; L]);

impl<const L: usize> CanonicalBytes<L> {
    pub fn new(bytes: [u8; L]) -> Self {
        Self(bytes)
    }

    pub fn as_array(&self) -> &[u8; L] {
        &self.0
    }

    pub fn into_array(self) -> [u8; L] {
        self.0
    }

    pub fn try_from_slice(slice: &[u8]) -> Result<Self, ErrorCode> {
        let bytes: [u8; L] = slice.try_into().map_err(|_| ErrorCode::ENoncanonical)?;
        Ok(Self(bytes))
    }
}

pub trait CanonicalCodec<const L: usize>: Sized {
    fn encode_symbol(sym: Self) -> CanonicalBytes<L>;
    fn decode_symbol(bytes: CanonicalBytes<L>) -> Result<Self, ErrorCode>;
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalBytes, CanonicalCodec, ErrorCode};

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DemoSymbol {
        A,
        B,
        C,
    }

    impl CanonicalCodec<1> for DemoSymbol {
        fn encode_symbol(sym: Self) -> CanonicalBytes<1> {
            let b = match sym {
                DemoSymbol::A => [0u8],
                DemoSymbol::B => [1u8],
                DemoSymbol::C => [2u8],
            };
            CanonicalBytes::new(b)
        }

        fn decode_symbol(bytes: CanonicalBytes<1>) -> Result<Self, ErrorCode> {
            match bytes.into_array()[0] {
                0 => Ok(DemoSymbol::A),
                1 => Ok(DemoSymbol::B),
                2 => Ok(DemoSymbol::C),
                _ => Err(ErrorCode::ENoncanonical),
            }
        }
    }

    #[test]
    fn canonical_codec_roundtrip() {
        let syms = [DemoSymbol::A, DemoSymbol::B, DemoSymbol::C];
        for s in syms {
            let encoded = DemoSymbol::encode_symbol(s);
            let decoded = DemoSymbol::decode_symbol(encoded).expect("decode should succeed");
            assert_eq!(decoded, s);
        }
    }

    #[test]
    fn canonical_codec_rejects_malformed() {
        let malformed = CanonicalBytes::<1>::new([255]);
        assert_eq!(
            DemoSymbol::decode_symbol(malformed),
            Err(ErrorCode::ENoncanonical)
        );

        let not_fixed = CanonicalBytes::<2>::try_from_slice(&[1]);
        assert_eq!(not_fixed, Err(ErrorCode::ENoncanonical));
    }
}
