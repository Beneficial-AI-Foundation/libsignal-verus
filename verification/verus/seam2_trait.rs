// Richer seam-2 specification: model `IdentityKeyStore` as a Rust *trait* so
// that the verification story tracks how real libsignal is structured.
//
// The real trait in `rust/protocol/src/storage/traits.rs:49-82` exposes
// async methods. We model the synchronous skeleton here (Verus has partial
// async support, but the invariant shape doesn't require it — the point is
// that the trait contract carries enough information for callers to
// discharge postconditions that the bodies alone could not).

use vstd::prelude::*;

verus! {

// -------- Abstract models closer to real libsignal ----------------------

#[derive(PartialEq, Eq, Copy, Clone)]
pub struct IdentityKey(pub u64);

#[derive(PartialEq, Eq, Copy, Clone)]
pub struct ProtocolAddress(pub u64);

// The ghost history of what a store has ever trusted. In real libsignal,
// this is persisted key-value state. Here it is a pure `Map` — Verus
// reasons about it symbolically.
pub type TrustMap = Map<ProtocolAddress, IdentityKey>;

// Trait counterpart to `storage::traits::IdentityKeyStore`. The `ghost`
// accessor `trusted@` exposes the abstract trust map; the executable
// methods are related to it via their postconditions.
pub trait IdentityKeyStore {
    // Ghost view: the abstract trust relation.
    spec fn trusted(&self) -> TrustMap;

    // `is_trusted_identity`: pure query.
    fn is_trusted_identity(&self, addr: ProtocolAddress, key: IdentityKey) -> (b: bool)
        ensures
            b == (self.trusted().contains_key(addr) && self.trusted()[addr] == key);

    // `save_identity`: extend the trust map with a new `(addr, key)` entry.
    fn save_identity(&mut self, addr: ProtocolAddress, key: IdentityKey)
        ensures
            self.trusted() == old(self).trusted().insert(addr, key);
}

// -------- Sender certificate: matches real libsignal's public shape -----

// In real libsignal `sender_uuid: String`. We keep the spirit (caller-chosen,
// not cryptographically bound to the store) with a ProtocolAddress — the
// typing of that field is seam 3's concern, not seam 2's.
pub struct SenderCertificate {
    pub sender_uuid: ProtocolAddress,
    pub key: IdentityKey,
}

pub struct Usmc {
    pub sender_uuid: ProtocolAddress,
    pub sender_key: IdentityKey,
    pub contents: u64,
}

// -------- The current-libsignal shape: trust-violating -------------------

pub fn ss_decrypt_to_usmc_bad<S: IdentityKeyStore>(
    cert: SenderCertificate,
    contents: u64,
    store: &S,
) -> (result: Usmc)
    ensures
        store.trusted().contains_key(result.sender_uuid),
        store.trusted()[result.sender_uuid] == result.sender_key,
{
    // Matches the real `sealed_sender_decrypt_to_usmc` — returns the
    // certificate's identity verbatim, without consulting the store.
    Usmc { sender_uuid: cert.sender_uuid, sender_key: cert.key, contents }
}

// -------- The fixed shape: perform the trust check via the trait --------

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

// -------- Caller pattern: composition across the trait boundary ---------

// A hypothetical caller that uses the fixed version and then dispatches
// further work based on the (now-trusted) sender identity. Verus checks
// that the caller's own postconditions discharge from the trait-level
// trust guarantee — no duplicate check required.
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

fn main() {}
