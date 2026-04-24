//! Seam-2 specification run through `cargo verus verify`.
//!
//! This is the same trait-based skeleton as `verification/verus/seam2_trait.rs`,
//! repackaged as a proper Cargo crate that uses the production Verus workflow
//! (matching `~/git_repos/baif/dalek-verus`). Running
//!
//!     cargo verus verify
//!
//! from this crate's directory reports verification results from the same
//! pipeline that curve25519-dalek uses.
//!
//! The spec intentionally mirrors `rust/protocol/src/storage/traits.rs`
//! (`IdentityKeyStore`) and `rust/protocol/src/sealed_sender.rs`
//! (`SenderCertificate`, `sealed_sender_decrypt_to_usmc`) at the type level,
//! modulo async. The bodies are abstract stand-ins; the `ensures` clauses are
//! the contract we want the real functions to satisfy.

#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use vstd::prelude::*;

verus! {

// -------- Abstract models mirroring libsignal types ---------------------

#[derive(PartialEq, Eq, Copy, Clone)]
pub struct IdentityKey(pub u64);

#[derive(PartialEq, Eq, Copy, Clone)]
pub struct ProtocolAddress(pub u64);

/// Ghost view of an IdentityKeyStore: the trust map from address to key.
/// Real libsignal persists this on disk; we work with the abstract relation.
pub type TrustMap = Map<ProtocolAddress, IdentityKey>;

/// Mirror of `rust/protocol/src/storage/traits.rs:49-82` (sync-ified).
pub trait IdentityKeyStore {
    /// Ghost accessor for the abstract trust map.
    spec fn trusted(&self) -> TrustMap;

    /// `fn is_trusted_identity(addr, key, direction) -> bool`
    /// — we drop `direction` to match `InMemIdentityKeyStore`'s semantics
    /// (see `rust/protocol/src/storage/inmem.rs:82` — the parameter is
    /// prefixed `_direction`).
    fn is_trusted_identity(&self, addr: ProtocolAddress, key: IdentityKey) -> (b: bool)
        ensures
            b == (self.trusted().contains_key(addr) && self.trusted()[addr] == key);

    /// `fn save_identity(addr, key) -> IdentityChange`
    fn save_identity(&mut self, addr: ProtocolAddress, key: IdentityKey)
        ensures
            self.trusted() == old(self).trusted().insert(addr, key);
}

/// Mirror of `rust/protocol/src/sealed_sender.rs:199-272`.
/// In real libsignal `sender_uuid: String`; we use `ProtocolAddress` since
/// the seam-2 invariant is independent of the sender-kind typing (seam 3 is
/// a separate concern handled in `Libsignal/Specs/Seam3.lean`).
pub struct SenderCertificate {
    pub sender_uuid: ProtocolAddress,
    pub key: IdentityKey,
}

pub struct Usmc {
    pub sender_uuid: ProtocolAddress,
    pub sender_key: IdentityKey,
    pub contents: u64,
}

// -------- Current libsignal shape --------------------------------------

/// Matches `sealed_sender_decrypt_to_usmc` at
/// `rust/protocol/src/sealed_sender.rs:1832-1956`: unwrap the SSS envelope,
/// return the identity from the (server-signed) certificate, do NOT consult
/// the IdentityKeyStore.
///
/// The `ensures` clause encodes the property a safe receiver needs — the
/// returned sender's key matches what the store trusts for that address.
/// Verus rejects this: the body does not establish that property.
pub fn ss_decrypt_to_usmc_bad<S: IdentityKeyStore>(
    cert: SenderCertificate,
    contents: u64,
    store: &S,
) -> (result: Usmc)
    ensures
        store.trusted().contains_key(result.sender_uuid),
        store.trusted()[result.sender_uuid] == result.sender_key,
{
    Usmc { sender_uuid: cert.sender_uuid, sender_key: cert.key, contents }
}

// -------- Proposed fix: perform the trust check ------------------------

/// The proposed fix: call `is_trusted_identity` before returning; if the
/// store does not already trust the certificate's (addr, key) pair, return
/// `None`.  Verus accepts this — the `Some` branch is reached only when
/// `is_trusted_identity` returned `true`, which by the trait's ensures
/// means the trust map agrees.
pub fn ss_decrypt_to_usmc_fixed<S: IdentityKeyStore>(
    cert: SenderCertificate,
    contents: u64,
    store: &S,
) -> (result: Option<Usmc>)
    ensures
        match result {
            Some(usmc) =>
                store.trusted().contains_key(usmc.sender_uuid)
                && store.trusted()[usmc.sender_uuid] == usmc.sender_key,
            None => true,
        },
{
    if store.is_trusted_identity(cert.sender_uuid, cert.key) {
        Some(Usmc { sender_uuid: cert.sender_uuid, sender_key: cert.key, contents })
    } else {
        None
    }
}

// -------- Downstream caller that inherits the trust guarantee ----------

/// A call site that composes on top of the fixed decryption. Verus checks
/// that the caller's own postcondition discharges from the trait-level
/// trust contract, without re-running `is_trusted_identity`. This is the
/// payoff: inside real libsignal, `session_cipher::message_decrypt_*` and
/// `group_cipher::group_decrypt` can rely on the upstream guarantee.
pub fn caller_accepts_only_trusted<S: IdentityKeyStore>(
    cert: SenderCertificate,
    contents: u64,
    store: &S,
) -> (accepted: Option<Usmc>)
    ensures
        match accepted {
            Some(u) => store.trusted().contains_key(u.sender_uuid)
                      && store.trusted()[u.sender_uuid] == u.sender_key,
            None => true,
        },
{
    ss_decrypt_to_usmc_fixed(cert, contents, store)
}

} // verus!
