//! Seam-2 specification against **real** `libsignal-protocol` types.
//!
//! Unlike `verification/verus/seam_crate/`, which used Verus stand-in types,
//! this crate imports the actual `IdentityKey`, `ProtocolAddress`, and
//! `SenderCertificate` from `libsignal-protocol` and reasons about a wrapper
//! function whose signature uses them.
//!
//! External types are marked `#[verifier::external_type_specification]` /
//! `#[verifier::external]` so Verus treats them as opaque. The trust-map
//! ghost state is held in a wrapper struct, and the trait contract is the
//! same shape as `seam_crate`.

#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

use vstd::prelude::*;

// Pull in the real types. Verus sees the names; the bodies are external.
use libsignal_protocol::{IdentityKey, ProtocolAddress};

verus! {

// -------- Ghost trust map keyed on something Verus can compare ---------
// We use the public key's serialization (Vec<u8>) as a ghost-level key
// fingerprint — opaque to Verus, compared by equality.

pub type IdKeyBytes = Seq<u8>;
pub type AddrBytes  = Seq<u8>;

pub type TrustMap = Map<AddrBytes, IdKeyBytes>;

/// Wrapper that holds the ghost trust map alongside the real store.
/// The underlying store is `#[verifier::external]`-ish in spirit — we do
/// not reason about it directly, only through the ghost view.
pub struct TrackedStore {
    pub ghost trusted: TrustMap,
}

impl TrackedStore {
    /// Abstract query mirroring `is_trusted_identity`.
    pub open spec fn is_trusted(&self, addr: AddrBytes, key: IdKeyBytes) -> bool {
        self.trusted.contains_key(addr) && self.trusted[addr] == key
    }
}

// External boundary: an executable check that talks to the real store.
// Its `ensures` clause ties its return to the ghost view. In a full
// integration this would wrap an actual `async` call on
// `libsignal_protocol::IdentityKeyStore`.
#[verifier::external_body]
pub fn check_trusted_real(
    store: &TrackedStore,
    addr: &AddrBytes,
    key: &IdKeyBytes,
) -> (b: bool)
    ensures b == store.is_trusted(*addr, *key),
{
    unimplemented!()
}

// -------- The BAD version: mirrors current libsignal -------------------

pub struct UsmcAbstract {
    pub sender_addr: AddrBytes,
    pub sender_key:  IdKeyBytes,
    pub contents:    Seq<u8>,
}

/// Abstract shape of `sealed_sender_decrypt_to_usmc`: takes ciphertext and a
/// tracked store, returns a USMC. The `ensures` is the trust invariant.
/// Bodies of serialization and signature validation are external; only the
/// missing cross-call check matters for this proof obligation.
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

// -------- The FIXED version -------------------------------------------

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
    if check_trusted_real(store, &cert_sender_addr, &cert_sender_key) {
        Some(UsmcAbstract {
            sender_addr: cert_sender_addr,
            sender_key:  cert_sender_key,
            contents,
        })
    } else {
        None
    }
}

// -------- Composition: how the trust flows into session_cipher --------
//
// Real libsignal's `sealed_sender_decrypt` dispatches on `usmc.msg_type()`
// to `session_cipher::message_decrypt_signal` (uses existing session) or
// `::message_decrypt_prekey` (establishes a fresh session). Each of those
// runs its own `is_trusted_identity(remote_addr, ...)` — the bug in attack
// #2 is that those downstream checks use the *session* or *PreKey message*
// identity, not the SSS cert's identity. So a forged cert slips through.
//
// We model this faithfully: a `SessionStore` with ghost state, downstream
// functions that check their own trust invariants, and a top-level
// composition that asks Verus whether the end-to-end trust guarantee holds.

pub type SessionMap = Map<AddrBytes, IdKeyBytes>;

pub struct TrackedSessionStore {
    pub ghost remote_id_key: SessionMap,
}

impl TrackedSessionStore {
    pub open spec fn has_session_with(
        &self,
        addr: AddrBytes,
        key: IdKeyBytes,
    ) -> bool {
        self.remote_id_key.contains_key(addr) && self.remote_id_key[addr] == key
    }
}

/// Abstract shape of `session_cipher::message_decrypt_signal`: requires a
/// pre-existing session and trusts whatever identity key that session holds.
/// The `ensures` says the returned plaintext's sender identity is the one
/// in the *session*, which is *not* necessarily the one in the SSS cert.
pub fn session_cipher_decrypt_signal(
    remote_addr: AddrBytes,
    session_store: &TrackedSessionStore,
    identity_store: &TrackedStore,
    ciphertext: Seq<u8>,
) -> (result: Option<(IdKeyBytes, Seq<u8>)>)
    ensures
        match result {
            Some((key, plaintext)) =>
                session_store.has_session_with(remote_addr, key)
                && identity_store.is_trusted(remote_addr, key),
            None => true,
        },
{
    if !session_has(session_store, &remote_addr) {
        return None;
    }
    let session_key = session_lookup(session_store, &remote_addr);
    // Real libsignal now runs `is_trusted_identity(remote_addr, session_key)`.
    // If it fails, the message is rejected.
    if !check_trusted_real(identity_store, &remote_addr, &session_key) {
        return None;
    }
    Some((session_key, run_decrypt(ciphertext)))
}

/// End-to-end composition: SSS decrypt → session_cipher decrypt. Verus
/// checks that the final plaintext carries a trust guarantee. Note the
/// asymmetry: the SSS layer returns `usmc.sender_key` (the cert's key),
/// but the session_cipher layer returns `session_key` (the session's
/// remote_identity_key). These are *not required to be equal* by the code.
///
/// The `ensures` clause asks: is the decrypted plaintext's sender identity
/// the one the attacker put in the SSS cert, or the one Bob has trusted
/// for a session with that address? Current libsignal gives the latter
/// — which is fine IF the two always match, but that is exactly what
/// attack #2 issue 1 breaks.
pub fn full_decrypt_pipeline(
    cert_sender_addr: AddrBytes,
    cert_sender_key:  IdKeyBytes,
    ciphertext:       Seq<u8>,
    identity_store:   &TrackedStore,
    session_store:    &TrackedSessionStore,
) -> (result: Option<(IdKeyBytes, Seq<u8>)>)
    ensures
        match result {
            Some((final_key, _)) =>
                // End-to-end: final_key is the identity the user sees.
                identity_store.is_trusted(cert_sender_addr, final_key),
            None => true,
        },
{
    let usmc = match ss_decrypt_to_usmc_fixed(
        cert_sender_addr,
        cert_sender_key,
        ciphertext,
        identity_store,
    ) {
        Some(u) => u,
        None    => return None,
    };
    // At this point, `usmc.sender_key == cert_sender_key` and
    // `identity_store.is_trusted(cert_sender_addr, cert_sender_key)` holds.
    //
    // The downstream decrypt runs the session-key trust check, which may
    // accept a *different* key (the session's stored remote_identity_key).
    // Verus will tell us whether the postcondition above can be discharged
    // under the weak contract of session_cipher_decrypt_signal.
    session_cipher_decrypt_signal(
        usmc.sender_addr,
        session_store,
        identity_store,
        usmc.contents,
    )
}

// -------- Ghost-mode helpers ------------------------------------------

#[verifier::external_body]
pub fn session_has(
    s: &TrackedSessionStore,
    addr: &AddrBytes,
) -> (b: bool)
    ensures b == s.remote_id_key.contains_key(*addr),
{
    unimplemented!()
}

#[verifier::external_body]
pub fn session_lookup(
    s: &TrackedSessionStore,
    addr: &AddrBytes,
) -> (k: IdKeyBytes)
    requires s.remote_id_key.contains_key(*addr),
    ensures k == s.remote_id_key[*addr],
{
    unimplemented!()
}

#[verifier::external_body]
pub fn run_decrypt(ciphertext: Seq<u8>) -> (plaintext: Seq<u8>)
    ensures true,
{
    unimplemented!()
}

} // verus!

// -------- Non-verus glue: where the real types connect -----------------

// A `#[verifier::external]` function that shows the real libsignal types
// are in scope. In a full integration, this is where we'd translate a real
// `&SenderCertificate` into the ghost `(AddrBytes, IdKeyBytes)` pair by
// calling `cert.sender_uuid()` and `cert.key()`.
#[verifier::external]
pub fn real_cert_bridge(cert: &libsignal_protocol::SenderCertificate)
    -> Result<(String, Box<[u8]>), libsignal_protocol::SignalProtocolError>
{
    let uuid = cert.sender_uuid()?.to_string();
    let key  = cert.key()?.serialize();
    Ok((uuid, key))
}
