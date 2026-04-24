// Seam-2 specification in Verus.
//
// Goal: express the missing cross-call invariant in
// sealed_sender_decrypt_to_usmc — that the sender-certificate's identity key
// must match the identity key Bob's IdentityKeyStore has recorded for that
// sender — and show that Verus rejects a version that does not enforce it.
//
// This is a *specification experiment*, not an extraction of real libsignal
// code. It models the data flow abstractly; the payoff is that the shape of
// the `ensures` clause transfers 1:1 to the real Rust code if someone
// integrates Verus into the libsignal build.

use vstd::prelude::*;

verus! {

// -------- Abstract models -----------------------------------------------

#[derive(PartialEq, Eq, Copy, Clone)]
pub struct IdentityKey(pub u64);

#[derive(PartialEq, Eq, Copy, Clone)]
pub struct ProtocolAddress(pub u64);

// `IdentityKeyStore` carries a ghost mapping from address to the one
// identity key Bob currently trusts for that address.  The field is `ghost`
// because in real libsignal it lives on disk / across async I/O; for the
// spec we only care about the abstract relation.
pub struct IdentityKeyStore {
    pub ghost trusted: Map<ProtocolAddress, IdentityKey>,
}

impl IdentityKeyStore {
    // Spec-level predicate mirroring `is_trusted_identity` in the real trait.
    pub open spec fn is_trusted(self, addr: ProtocolAddress, key: IdentityKey) -> bool {
        self.trusted.contains_key(addr) && self.trusted[addr] == key
    }
}

// Fake "server-validated" sender certificate: the server signature has
// already been checked, so the attacker can't tamper with these fields
// individually — but a malicious server can emit arbitrary (uuid, key) pairs.
pub struct SenderCertificate {
    pub sender_uuid: ProtocolAddress,
    pub key: IdentityKey,
}

// The decrypted SSS payload that the rest of libsignal then hands off to
// session_cipher.
pub struct Usmc {
    pub sender_uuid: ProtocolAddress,
    pub sender_key: IdentityKey,
    pub contents: u64,
}

// -------- BAD version: current libsignal behavior -----------------------

// Abstract shape of the real `sealed_sender_decrypt_to_usmc`: unwrap the
// SSS layer, take the identity from the (server-signed) certificate, and
// return. Does NOT consult the IdentityKeyStore.
//
// The `ensures` clause encodes what a safe receiver actually needs: the
// returned sender's key matches what the store trusts for that address.
//
// Verus should reject this — the body does not establish the postcondition.
pub fn ss_decrypt_to_usmc_bad(
    cert: SenderCertificate,
    contents: u64,
    store: &IdentityKeyStore,
) -> (result: Usmc)
    ensures
        store.is_trusted(result.sender_uuid, result.sender_key),
{
    Usmc { sender_uuid: cert.sender_uuid, sender_key: cert.key, contents }
}

// -------- FIXED version 1: push the obligation up to the caller ---------

// Same body, but the function now declares a `requires` matching the
// postcondition. Verus accepts it: the caller has to discharge the
// obligation before calling. That is the specification the real libsignal
// code is implicitly relying on but never stating.
pub fn ss_decrypt_to_usmc_fixed_precondition(
    cert: SenderCertificate,
    contents: u64,
    store: &IdentityKeyStore,
) -> (result: Usmc)
    requires
        store.is_trusted(cert.sender_uuid, cert.key),
    ensures
        store.is_trusted(result.sender_uuid, result.sender_key),
{
    Usmc { sender_uuid: cert.sender_uuid, sender_key: cert.key, contents }
}

// -------- FIXED version 2: perform the check inside, return Option ------

// Model of `is_trusted_identity` as an external (trait-call) function whose
// result is tied to the ghost `trusted` map. In real libsignal this is an
// async method on `dyn IdentityKeyStore`.
#[verifier::external_body]
fn check_trusted(
    store: &IdentityKeyStore,
    addr: ProtocolAddress,
    key: IdentityKey,
) -> (b: bool)
    ensures b == store.is_trusted(addr, key),
{
    unimplemented!()
}

// This version matches the shape of the actual fix we propose: add the
// check to `sealed_sender_decrypt_to_usmc` itself. Verus accepts it.
pub fn ss_decrypt_to_usmc_fixed_check(
    cert: SenderCertificate,
    contents: u64,
    store: &IdentityKeyStore,
) -> (result: Option<Usmc>)
    ensures
        match result {
            Some(usmc) => store.is_trusted(usmc.sender_uuid, usmc.sender_key),
            None       => true,
        },
{
    if check_trusted(store, cert.sender_uuid, cert.key) {
        Some(Usmc { sender_uuid: cert.sender_uuid, sender_key: cert.key, contents })
    } else {
        None
    }
}

} // verus!

fn main() {}
