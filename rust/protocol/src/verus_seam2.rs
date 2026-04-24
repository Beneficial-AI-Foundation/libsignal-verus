//! ============================================================================
//! verus-verify patch  (new file; not in upstream libsignal @ 0a58e80b)
//! ============================================================================
//!
//! In-place Verus specification for the seam-2 invariant
//! (`docs/shared_state_seams.md` §Seam 2): `sealed_sender_decrypt_to_usmc`
//! does not cross-check the sender certificate's identity key against
//! the receiver's IdentityKeyStore.
//!
//! Loaded only under the `verus-verify` feature. Registered from
//! `lib.rs` (which has a matching verus-verify patch block). Verified
//! in-place as part of `libsignal-protocol` itself:
//!
//!     cargo verus verify -p libsignal-protocol --features verus-verify
//!
//! Requires Verus >= 0.2026.04.19 (earlier releases panic in
//! `rust_verify::external::get_attributes_for_automatic_derive` on the
//! `derive_more::Into` expansions in `state/*.rs`; see the bisection
//! writeup in `docs/shared_state_seams.md`).

#![allow(unused_imports, unused_variables, dead_code)]

use vstd::prelude::*;

verus! {

// -------- Ghost trust map ----------------------------------------------

pub type AddrBytes  = Seq<u8>;
pub type IdKeyBytes = Seq<u8>;
pub type TrustMap   = Map<AddrBytes, IdKeyBytes>;

pub struct TrackedStore {
    pub ghost trusted: TrustMap,
}

impl TrackedStore {
    pub open spec fn is_trusted(&self, addr: AddrBytes, key: IdKeyBytes) -> bool {
        self.trusted.contains_key(addr) && self.trusted[addr] == key
    }
}

// -------- External bridge to a (future) real IdentityKeyStore ----------

#[verifier::external_body]
pub fn check_trusted(
    store: &TrackedStore,
    addr: &AddrBytes,
    key: &IdKeyBytes,
) -> (b: bool)
    ensures b == store.is_trusted(*addr, *key),
{
    unimplemented!()
}

pub struct UsmcAbstract {
    pub sender_addr: AddrBytes,
    pub sender_key:  IdKeyBytes,
    pub contents:    Seq<u8>,
}

// -------- Current libsignal shape: rejected by Verus -------------------

/// Models `sealed_sender_decrypt_to_usmc` as it exists today: returns the
/// cert's identity verbatim, without consulting the IdentityKeyStore.
/// The `ensures` clause encodes the trust invariant a safe receiver
/// needs. Verus rejects this — the body cannot establish the postcondition.
pub fn ss_decrypt_to_usmc_bad(
    cert_sender_addr: AddrBytes,
    cert_sender_key:  IdKeyBytes,
    contents:         Seq<u8>,
    store:            &TrackedStore,
) -> (result: UsmcAbstract)
    ensures
        store.trusted.contains_key(result.sender_addr),
        store.trusted[result.sender_addr] == result.sender_key,
{
    UsmcAbstract {
        sender_addr: cert_sender_addr,
        sender_key:  cert_sender_key,
        contents,
    }
}

// -------- Proposed fix: call the store's trust check ------------------

/// Adds the missing cross-check. Verus accepts this — the `Some` branch
/// is reached only when `check_trusted` returned `true`, which by its
/// `ensures` clause means the trust map agrees.
pub fn ss_decrypt_to_usmc_fixed(
    cert_sender_addr: AddrBytes,
    cert_sender_key:  IdKeyBytes,
    contents:         Seq<u8>,
    store:            &TrackedStore,
) -> (result: Option<UsmcAbstract>)
    ensures
        match result {
            Some(u) =>
                u.sender_addr == cert_sender_addr
                && u.sender_key == cert_sender_key
                && store.trusted.contains_key(u.sender_addr)
                && store.trusted[u.sender_addr] == u.sender_key,
            None => true,
        },
{
    if check_trusted(store, &cert_sender_addr, &cert_sender_key) {
        Some(UsmcAbstract {
            sender_addr: cert_sender_addr,
            sender_key:  cert_sender_key,
            contents,
        })
    } else {
        None
    }
}

} // verus!

// -------- Non-verus glue: bridge from real SenderCertificate ----------

/// Narrow bridge into the real libsignal `SenderCertificate`. In a full
/// integration this is where `(AddrBytes, IdKeyBytes)` come from. Being
/// outside the `verus!` block makes it external to Verus by default.
pub fn real_cert_bridge(cert: &crate::SenderCertificate)
    -> crate::Result<(String, Box<[u8]>)>
{
    let uuid = cert.sender_uuid()?.to_string();
    let key  = cert.key()?.serialize();
    Ok((uuid, key))
}
