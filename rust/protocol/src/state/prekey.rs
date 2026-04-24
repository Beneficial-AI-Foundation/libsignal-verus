//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

use prost::Message;

use crate::proto::storage::PreKeyRecordStructure;
use crate::{KeyPair, PrivateKey, PublicKey, Result, SignalProtocolError};

// ============================================================================
// BEGIN verus-verify patch  (differs from upstream libsignal)
// ----------------------------------------------------------------------------
// Upstream:
//     #[derive(
//         Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd,
//         derive_more::From, derive_more::Into,
//     )]
//     pub struct PreKeyId(u32);
//
// Patch: gate the `derive_more::Into` derive to non-verus builds, and add an
// equivalent hand-written `impl From<PreKeyId> for u32` under the verus-verify
// feature.
//
// Rationale: `#[derive(derive_more::Into)]` expands to
// `#[automatically_derived] impl From<PreKeyId> for u32 { ... }`.
// Verus's `rust_verify::external::get_attributes_for_automatic_derive` walker
// (see `external.rs:656` in Verus 0.2026.04.19) unconditionally calls
// `.def_id()` on the `self_ty` of every `#[automatically_derived]` impl;
// when `self_ty` is a primitive like `u32`, `path.res` is
// `Res::PrimTy(Uint(u32))` which has no DefId, and the walker panics.
//
// The hand-written impl is semantically identical (same `From<PreKeyId> for u32`
// trait, same body), but does not carry `#[automatically_derived]` and so
// bypasses the panicking code path. No callsite changes are required; every
// caller that uses `u32::from(id)` or `id.into()` continues to work under both
// feature states.
//
// See: docs/VERIFICATION_REPORT.md §"Verus panics and workarounds" (panic 1).
// ============================================================================

/// A unique identifier selecting among this client's known pre-keys.
#[derive(
    Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, derive_more::From,
)]
#[cfg_attr(not(feature = "verus-verify"), derive(derive_more::Into))]
pub struct PreKeyId(u32);

#[cfg(feature = "verus-verify")]
impl From<PreKeyId> for u32 {
    fn from(id: PreKeyId) -> Self { id.0 }
}
// ============================================================================
// END verus-verify patch
// ============================================================================

impl fmt::Display for PreKeyId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone)]
pub struct PreKeyRecord {
    pre_key: PreKeyRecordStructure,
}

impl PreKeyRecord {
    pub fn new(id: PreKeyId, key: &KeyPair) -> Self {
        let public_key = key.public_key.serialize().to_vec();
        let private_key = key.private_key.serialize().to_vec();
        Self {
            pre_key: PreKeyRecordStructure {
                id: id.into(),
                public_key,
                private_key,
            },
        }
    }

    pub fn deserialize(data: &[u8]) -> Result<Self> {
        Ok(Self {
            pre_key: PreKeyRecordStructure::decode(data)
                .map_err(|_| SignalProtocolError::InvalidProtobufEncoding)?,
        })
    }

    pub fn id(&self) -> Result<PreKeyId> {
        Ok(self.pre_key.id.into())
    }

    pub fn key_pair(&self) -> Result<KeyPair> {
        Ok(KeyPair::from_public_and_private(
            &self.pre_key.public_key,
            &self.pre_key.private_key,
        )?)
    }

    pub fn public_key(&self) -> Result<PublicKey> {
        Ok(PublicKey::deserialize(&self.pre_key.public_key)?)
    }

    pub fn private_key(&self) -> Result<PrivateKey> {
        Ok(PrivateKey::deserialize(&self.pre_key.private_key)?)
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        Ok(self.pre_key.encode_to_vec())
    }
}
