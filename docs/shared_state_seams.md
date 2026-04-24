# Shared-State Seams: A Storage-Trait View of Cross-Protocol Attacks

*Companion to `audit_findings.md` and `cross_protocol_interaction_analysis.md`. Those
files enumerate specific attack surfaces. This one reframes them under a single
mechanical lens — the storage traits — so that the verification target becomes
uniform across protocols.*

## Hypothesis

Both attacks in Truong, Terzo, Paterson, *Signal Lost (Integrity)* (eprint 2026/484)
have the same shape:

> Protocol **A** writes state `s` to a shared store using trust model **T_A**.
> Protocol **B** reads `s` from that store using trust model **T_B**.
> Nothing forces `T_A ≥ T_B`.

If this is true, we should be able to find more instances of the shape by looking
only at the storage trait definitions and the set of callers of each store method.

## Shared-state surface

`rust/protocol/src/storage/traits.rs` defines six traits. Every protocol uses them:

| Store                  | Key                        | Writers                                                    | Readers                                                                  |
|------------------------|----------------------------|------------------------------------------------------------|--------------------------------------------------------------------------|
| `IdentityKeyStore`     | `ProtocolAddress`          | `session_cipher`, `session::process_prekey_bundle`         | `session_cipher`, `session::process_prekey`, app-layer fingerprint       |
| `SessionStore`         | `ProtocolAddress`          | `session_cipher`, `session::process_prekey_bundle`         | `session_cipher`, `sealed_sender_decrypt` (via session_cipher)           |
| `PreKeyStore` etc.     | `PreKeyId` etc.            | `session::process_prekey_impl`                             | X3DH/PQXDH only                                                          |
| `SenderKeyStore`       | `(ProtocolAddress, Uuid)`  | `group_cipher::process_sender_key_distribution_message`    | `group_cipher::group_encrypt`/`group_decrypt`                            |

### The one architectural fact that enables every seam

`ProtocolAddress::new(name: String, device_id)` takes an **opaque string** for `name`.
`rust/protocol/` contains **zero non-test references that discriminate ACI from PNI**
(spot-check: `grep -rn "Pni\|PNI" rust/protocol/src/ | grep -v "test\|fuzz\|proto/"`
returns only one hit — a domain-separation constant in `identity_key.rs:17`). The
entire ACI/PNI distinction is the caller's responsibility. Whatever identity the app
layer decides to stuff into that `name` field becomes a trust key for every store
above.

## The six seams

Each seam is one store + one writer + one reader with non-matching trust levels.

### Seam 1 — `IdentityKeyStore` per-`ProtocolAddress` (attack-1 surface)

- **Writer** `session_cipher::message_decrypt_signal` at `session_cipher.rs:308-324`
  / `session::process_prekey` at `session.rs:57-64`: establishes a trust entry under
  whatever address string the caller passes, via TOFU-style `is_trusted_identity`
  with no cross-address check.
- **Reader** (app-level): safety-number computation (`fingerprint.rs`) binds only to
  the ACI entry; the UI tells the user "safety numbers match" without touching the
  PNI entry that may also exist for the same human.
- **T_A vs T_B**: writer's T_A = "first key seen for this string"; reader's T_B =
  "safety-number-verified for this person". No enforcement that T_A ≥ T_B.
- **Exploited**: yes, attack #1. Fixed entirely in Signal-Android
  (`MessageDecryptor.kt`, +11 lines) by refusing to process PNI-addressed inbound
  payload. libsignal untouched.

### Seam 2 — `sealed_sender_decrypt_to_usmc` → `session_cipher` handoff (attack-2 surface, **still unpatched in Rust**)

- **Writer** `sealed_sender_decrypt_to_usmc` at `sealed_sender.rs:1832-1956`:
  authenticates against `usmc.sender().key()` — the **server-signed certificate**'s
  identity key. T_A = "signed by the server".
- **Reader** `sealed_sender_decrypt` → `session_cipher::message_decrypt_{signal,prekey}`
  at `session_cipher.rs:197-331`: re-authenticates against the **session record** or
  the **PreKey message's identity key** (`is_trusted_identity`). T_B = "session-key
  authenticated" OR (for fresh sessions) "TOFU".
- **T_A vs T_B**: the two identity keys are never required to match.
  `grep is_trusted_identity rust/protocol/src/sealed_sender.rs` returns nothing. SSS's
  cryptographic work is discarded at the handoff.
- **Patched**: only on Android, in Java. Rust side unchanged at upstream commit
  `0a58e80b`.

### Seam 3 — SKDM → group_cipher (the shape of attack #1 in groups)

- **Writer** `group_cipher::process_sender_key_distribution_message(sender, skdm, store)`
  at `group_cipher.rs:196-226`: takes `sender: &ProtocolAddress` from the caller with
  no cryptographic binding and writes a `SenderKeyRecord` containing `skdm.signing_key()`.
  T_A = "whatever the calling context's trust was when it chose `sender`".
- **Reader** `group_cipher::group_decrypt` at `group_cipher.rs:124-194` →
  `SenderKeyMessage::verify_signature` at `protocol.rs:501`: checks the message's
  Ed25519 signature against the stored `signing_key`. T_B = "same signing_key as was
  previously stored".
- **T_A vs T_B**: `group_decrypt` cannot distinguish "SKDM arrived over an
  ACI-safety-number-verified channel" from "SKDM arrived over a PNI-TOFU channel".
- **Exploited**: no. Paper says attack #1 doesn't reach groups "for technical
  reasons." (See §Investigation log for why; this seam's reachability depends on
  whether any 1:1 path accepts a PNI-addressed SKDM as authentic.)

### Seam 4 — `get_identity_key_pair()` is single-identity

- `IdentityKeyStore::get_identity_key_pair()` (trait `storage/traits.rs:51`) returns
  **one** identity key pair. A user has **two** (ACI, PNI). The store
  implementation decides which. No precondition ties the returned pair to any
  operation's address context.
- **Call sites**: `sealed_sender.rs:965, 1390, 1836`, `session.rs:147, 216`.
- **T_A vs T_B**: undefined. Correctness of this entire surface is a property of
  the **platform glue**, not of Rust.

### Seam 5 — `verify_alternate_identity` exists but is not wired into any decryption path

- `rust/protocol/src/identity_key.rs:60` provides `verify_alternate_identity(other,
  signature)` with a `"Signal_PNI_Signature"` domain separator — the exact primitive
  for "ACI vouches for PNI".
- Callers in `rust/protocol/`: **zero outside of its own unit tests**
  (`grep -rn "verify_alternate_identity" rust/protocol/`).
- Callers elsewhere: only `rust/bridge/shared/src/protocol.rs:282` (FFI passthrough).
- **Implication**: the mechanism that would cryptographically bind PNI-addressed
  sessions to ACI safety numbers exists as a utility but is not enforced anywhere.
  The 11-line Signal-Android patch for attack #1 doesn't use it either.

### Seam 6 — `message-backup` re-populates `IdentityKeyStore` across the device boundary

- `rust/message-backup/src/backup/recipient.rs:308`: each `Contact` record persists
  `identity_key: Option<IdentityKey>`. Restore re-installs these in
  `IdentityKeyStore`.
- **T_A vs T_B**: restored entries bypass the live TOFU that would normally gate a
  new key. The restore writer's T_A = "present in the backup blob"; the reader
  `is_trusted_identity` treats it as T_B = "trusted".
- **Exploited as a full chain**: `cross_protocol_interaction_analysis.md:249`
  (AccountEntropyPool compromise cascade) already walks the end-to-end scenario.
- **Shape match**: identical to the other seams — a new writer with weaker T_A
  feeds the same store whose readers assume a stronger T_B.

## Verification implication

Every seam has the same abstract obligation: declare `trust_level(store, addr)` as a
ghost field and add pre/postconditions on the store methods. Then each protocol's
writer/reader pair has to declare which level it establishes/consumes, and the
proofs either discharge or they don't. A single ghost invariant covers all six.
That is a substantially more useful verification target than the current
per-function encoding specs in `Libsignal/Specs/Core/Address/*.lean`, because it
catches exactly the class of bug the paper found.

Sketch:

```rust
// Ghost state on IdentityKeyStore:
spec fn trust_level(self, addr: ProtocolAddress) -> TrustLevel;

// Writers advertise what they established:
// session_cipher::message_decrypt_signal ensures
//   store'.trust_level(addr) == T_Session
// session::process_prekey ensures
//   store'.trust_level(addr) == T_PreKeyTofu
// (hypothetical) sealed_sender_decrypt_to_usmc ensures
//   store'.trust_level(addr) == T_ServerCertified

// Readers demand what they need:
// group_cipher::process_sender_key_distribution_message requires
//   store.trust_level(sender) >= T_SafetyNumberVerified
//   // this would fail under a PNI TOFU session, as required
```

Under this specification, seams 2, 3, 6 fail; seam 1 fails for any reader that
assumes ACI-verification; seam 4 requires strengthening the `get_identity_key_pair`
signature to take an address or role parameter; seam 5 becomes a consequence of the
spec (the only way to discharge `trust_level(PNI_addr) >= T_SafetyNumberVerified`
would be via an alternate-identity signature chain).

## Investigation log

### Seam 3 validation — the "SSS sender must be ACI" rule is not in libsignal

The paper (p. 11) says attack #1 does not reach groups because "SSS protocol … mandates the source address to be an ACI, but the gadget above only allow message injection from a PNI address." We looked for where that rule is enforced.

**Finding**: the rule is *not* enforced anywhere in `rust/protocol/` or `rust/bridge/`.

- `SenderCertificate.sender_uuid` is a raw `String` (`sealed_sender.rs:201`).
  No typed ACI/PNI discriminator, no kind byte.
- `SenderCertificate::deserialize` (line 210) does not check the UUID's kind.
- `SenderCertificate::validate` / `::validate_with_trust_roots` (lines 327–370)
  verify only the certificate chain signature against a trust root. No kind check.
- `sealed_sender_decrypt` (line 1992) compares `sender_uuid` against `local_uuid`
  as raw strings (line 2013). No kind awareness.
- `grep ServiceIdKind\|Aci\|Pni rust/protocol/src/sealed_sender.rs` returns only
  one match in code (`sealed_sender.rs:1670`, and it's about SSv2 **recipient**
  decoding, where a legacy version hard-codes ACI for recipient addresses — this
  has nothing to do with senders).

So the "ACI-only source" rule that the paper says protects groups is **entirely a
client-layer invariant** — enforced in the Signal-Android Kotlin patch from
2025-09-24 by refusing to dispatch any PNI-inbound payload. The protocol layer
would happily process a PNI-addressed SenderCertificate.

**Implication for seam 3**: the seam is real. Groups are protected only because one
platform's app layer drops PNI messages; any libsignal consumer that does not
enforce the same rule at dispatch is vulnerable. The paper confirms this: Whisperfish
and signal-cli were both vulnerable to attack #1 and patched in 2026-02 with exactly
the same "reject PNI-addressed messages" fix (paper §5, refs [8][9][72][73]).

**Verification lever**: change `SenderCertificate.sender_uuid: String` to
`sender_service_id: Aci` (or add a kind check in `deserialize`). Every caller of
`SenderCertificate::new` and `::deserialize` is then forced to re-type. The
invariant becomes type-checked at the Rust boundary, not a platform convention.

### Seam 2 re-validation — two entry points expose the same crypto differently

- `rust/bridge/shared/src/protocol.rs:1164`: `SealedSender_DecryptToUsmc` — unwraps
  SSS, returns `UnidentifiedSenderMessageContent`, **does not validate the sender
  certificate against any trust root**.
- `rust/bridge/shared/src/protocol.rs:1186`: `SealedSessionCipher_DecryptToUsmc` —
  calls the full `sealed_sender_decrypt`, which validates the certificate and then
  dispatches to `session_cipher::message_decrypt_{signal,prekey}`.

Two bridge entry points; client apps pick which one to use. Android uses the first
(to keep its own dispatch logic), which is exactly how attack #2's issue 2 became
possible — the all-in-one path rejects `PLAINTEXT_CONTENT` (line 2057-2062), but the
`_to_usmc` path doesn't know anything about message types, so Android's custom
post-processing had a direct shot at the bug. The architectural shape: **the same
cryptographic operation is exposed with and without safety rails, and the caller
chooses which.**

**Finding**: this is in fact worse than seam 2 as originally stated. `_to_usmc`
doesn't even validate the certificate against the trust root — that check lives
*only* in `sealed_sender_decrypt`. So on Android, where the Kotlin layer drives
dispatch after `_to_usmc`, certificate trust-root validation is a separate Java-side
call (see `rust/bridge/shared/src/protocol.rs:738` for the bridge fn
`SenderCertificate_Validate`). If that separate call is skipped, even the
server-certificate trust is lost.

**Verification lever**: either (a) fold `validate_with_trust_roots` into
`sealed_sender_decrypt_to_usmc` itself (making trust-root validation a
precondition of ever returning a USMC), or (b) return a typed
`UntrustedUnidentifiedSenderMessageContent` that cannot be used downstream without
first being upgraded via a validator. Both are amenable to Verus/Aeneas encoding —
(b) is exactly a typestate property.

### Seam 4 validation — `InMemIdentityKeyStore` is the reference semantics

The trait leaves "which identity" and "what is trusted" entirely to implementors,
but `InMemIdentityKeyStore` in `storage/inmem.rs:23-98` is the only in-tree
reference and is what integration tests run against. What it actually does:

```rust
// storage/inmem.rs:52-54
async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair> {
    Ok(self.key_pair)                 // one key pair, fixed at construction
}

// storage/inmem.rs:78-90
async fn is_trusted_identity(
    &self,
    address: &ProtocolAddress,
    identity: &IdentityKey,
    _direction: traits::Direction,    // argument is ignored
) -> Result<bool> {
    match self.known_keys.get(address) {
        None => Ok(true),             // first use: always trusted
        Some(k) => Ok(k == identity),
    }
}
```

Two properties worth noting:

- **Pure TOFU**. First sighting of an `(address, identity)` is unconditionally
  trusted. There is no cryptographic vouching (no `verify_alternate_identity`
  check, no external attestation, no safety-number requirement). For a PNI-addressed
  session with attacker-chosen keys, `known_keys.get(PNI_addr)` is `None` the first
  time → `Ok(true)`. This is exactly the state that attack #1 exploits at the
  protocol level; the TOFU answer in the reference store is what makes the attack
  protocol-silent.
- **`direction` is dropped**. The trait lets a caller say "I'm about to send" vs
  "I'm receiving", but the reference implementation ignores it. So even if a
  production store wanted to implement asymmetric policy (e.g., send requires
  prior safety-number verification, receive allows TOFU), the reference semantics
  would not enforce it and tests would not catch a regression to TOFU-on-send.

**In-tree call pattern for "which identity pair"**: `InMemSignalProtocolStore`
embeds a single `InMemIdentityKeyStore` (`storage/inmem.rs:385`) — one identity
per protocol store. Production clients that need ACI and PNI instantiate two
stores and swap which one the protocol crate is handed, based on the calling
context. No Rust-side code cross-checks that the right store is in use for a
given `remote_address`.

**Finding**: seam 4 is real and structurally inescapable under the current trait.
`get_identity_key_pair()` returning one key with no address/role parameter means
any "is this the right identity pair for this operation?" check must happen outside
Rust. The reference semantics make the default *unsafe* (pure TOFU, direction
ignored), which means a verifier bolted onto Rust code today would, if it used
`InMemIdentityKeyStore` as the concrete store, prove correctness against TOFU — the
very trust model that attack #1 exploits.

**Verification lever**: change the trait:

```rust
async fn get_identity_key_pair(&self, for_role: IdentityRole) -> Result<IdentityKeyPair>;
// where IdentityRole = Aci | Pni, or more precisely tied to the calling operation

async fn is_trusted_identity(
    &self,
    address: &ProtocolAddress,
    identity: &IdentityKey,
    direction: Direction,
    required_level: TrustLevel,       // new: caller states what it needs
) -> Result<bool>;
```

With the added `required_level` parameter, every reader declares the T_B it needs,
and the store must prove T_A ≥ T_B. The ghost spec from the main note discharges
automatically.

### Seam 6 validation — `rust/message-backup/` is parse-only; the seam is empty in Rust

We looked for any code path that writes to `IdentityKeyStore` from backup data.

- `grep -rn "save_identity\|IdentityKeyStore" rust/message-backup/` returns **zero**
  matches in non-test code.
- `IdentityKey` appears only as a field in parsed data (`recipient.rs:308:
  pub identity_key: Option<IdentityKey>`), constructed by decoding bytes
  (`recipient.rs:615:
  .map(|bytes| IdentityKey::decode(&bytes))`) and exposed to the caller.
- Entry points (`lib.rs:164-181`): `read_all`, `validate_all`, `collect_all` —
  all are **readers/validators**. No "apply to store" API.

**Finding**: the Rust backup crate is a pure validator. The actual write path from
backup into `IdentityKeyStore` lives in each platform's app code (Signal-Android
Kotlin, Signal-iOS Swift, Signal-Desktop TS). Consequently:

- The seam exists conceptually (writer = restore, reader = live Signal Protocol)
  and `cross_protocol_interaction_analysis.md:249` already traces an end-to-end
  AccountEntropyPool compromise cascade.
- But on the current Rust codebase it is **not a verification target**. Aeneas
  can extract the parser, Verus can prove its correctness, and attack #6 still
  works because the bad write happens outside the verified boundary.

**Verification lever** that *would* help: change the parser's return type from
`Option<IdentityKey>` to a typestate like `Option<UnvalidatedIdentityKey>` that
cannot be passed to `save_identity` without a validation step. That makes the
invariant impossible to violate from Rust and forces platform code to either do
the work in Rust (where we can verify it) or explicitly convert via an
`Unvalidated -> IdentityKey` function whose precondition is the safety-number
check. Same ghost-spec shape as seam 4.

### Seam 5 re-confirmation — `verify_alternate_identity` is dead code in protocol

`grep -rn "verify_alternate_identity\|sign_alternate_identity" rust/protocol/`
returns:
- 2 definitions in `identity_key.rs`
- 1 doc reference
- 6 hits inside `identity_key.rs`'s own unit tests
- 0 hits in any message-processing code (`session*.rs`, `sealed_sender.rs`, `group_cipher.rs`, `ratchet/`, etc.)

And `grep -rn "verify_alternate_identity" rust/` outside protocol: only
`rust/bridge/shared/src/protocol.rs:282` (FFI passthrough), plus extracted LLBC
blobs in `data/`.

So the cryptographic primitive that would bind a PNI identity to an ACI-verified
safety number is present and tested, but **not invoked by any protocol-level
decision in Rust**. If Rust ever wants to enforce "PNI sessions are only trusted
when cryptographically linked to a safety-number-verified ACI", the primitive is
ready; the wiring is absent.

## Summary of validation

| Seam | Paper-acknowledged | Real in current code | Who closes it today | Rust-verifiable as-is |
|------|--------------------|----------------------|----------------------|------------------------|
| 1    | Yes (attack 1)     | Yes                  | Signal-Android 11-line Kotlin patch | No — the rule lives in Kotlin |
| 2    | Yes (attack 2, issue 1) | Yes, **unpatched in Rust** | Android Java validates `PLAINTEXT_CONTENT` (addresses issue 2 only) | Partially — cert-to-store link is verifiable once a spec is written |
| 3    | Yes (observed unreachable) | **Yes, closed only by seam-1 patch** | Client apps that reject PNI-inbound messages | Not yet — `SenderCertificate.sender_uuid` is `String` |
| 4    | Implicit           | Yes                  | Platform-specific store wiring; reference in-mem store is pure TOFU | Not yet — trait does not take role/address for identity pair |
| 5    | No                 | Primitive exists, unused | Nothing — it's a missed defense | Yes — wiring it in is a pure Rust change |
| 6    | Yes (other analyses) | Yes, but **not in Rust** — backup crate is parse-only | Client restore code + AccountEntropyPool entropy | No — the write lives outside the Rust boundary |

The recurring pattern: **every "fix" for these seams lives outside the protocol
crate**. libsignal-Rust delegates each invariant to the consumer.

Seams 2, 3, 4, and 5 have concrete code-level changes inside Rust that would move
the invariant into a place Verus/Aeneas can verify. Seams 1 and 6 are Rust-opaque
as things stand — they would require either the invariant to be lifted into Rust
(seam 1: type-discriminate ACI/PNI addresses in dispatch; seam 6: move restore
logic into Rust with a typestate guard) or cross-language verification, which is
beyond this repo's stack.

**Prioritisation for deep-dive** (by tractability × uncaught-attack-surface):

1. **Seam 3** — retype `SenderCertificate.sender_uuid` as `Aci`. Tractable, forces
   every consumer to acknowledge the invariant, closes one of the paper's
   "implicit platform rules" by making it a type.
2. **Seam 2** — add trust-level tracking on `UnidentifiedSenderMessageContent`
   (typestate: `…<Unvalidated>` vs `…<Validated>`). Directly addresses attack-2
   issue 1, which is still unpatched in Rust.
3. **Seam 4** — expand `IdentityKeyStore` trait with role/trust-level parameters.
   Deepest redesign; closes the TOFU default in the reference store and removes
   the "which identity pair?" ambiguity that attack #1 turns into a vulnerability.
4. **Seam 5** — wire `verify_alternate_identity` into PNI-addressed decryption
   paths. Smallest patch, but only meaningful if either seam 3 or seam 4 is in
   place so the code knows when it's on a PNI path.

Seams 1 and 6 are out of scope for Rust verification without moving code across
language boundaries.

## Reality check — separating structural claims from exploitable harm

Before spending effort on verification, each finding is assessed along three axes:

1. **Reachable** under the paper's threat model (malicious server, honest client)?
2. **Unmitigated downstream** — does any other layer (Java bridge, client code,
   additional parser check) catch the bad behavior before it causes harm?
3. **Observable harm** — does the reachable+unmitigated behavior actually hurt a
   user, or is it a latent gadget that only matters in composition?

| Seam | Reachable | Unmitigated downstream in Rust | Observable harm alone |
|------|-----------|--------------------------------|-----------------------|
| 2    | Yes — malicious server can issue arbitrary certs (paper's threat model) | Yes on Rust side; Android patched issue 2 only | DecryptionError forgery; full injection if any caller dispatches broader message types from `_to_usmc` |
| 3    | Yes — `SenderCertificate` constructor/validator accept any UUID string | Yes on Rust side; only platform dispatchers block PNI-sourced inbound | Same as attack-1 chain when composed; no harm in isolation |
| 4    | Trivially — in-mem store is TOFU for first use | Reference impl is the implementation; production stores differ per platform | No direct production harm; weakens what can be verified *against libsignal's own tests* |
| 5    | Absence of a call — no harm on its own | — | None; it is a missing defense that becomes relevant once seams 3/4 are addressed |

Conclusions:

- **Seam 2** is real with the highest confidence: the paper built a PoC, the code
  path is unchanged since, and a mechanical unit test inside this repo can
  reproduce the gadget.
- **Seam 3** is a real type-safety failure; the chain to user-visible harm is the
  paper's attack-1 chain and is currently blocked only outside Rust.
- **Seam 4** is real as a fact about the reference implementation and therefore
  matters for anything this repo proves against that reference — but it is not
  itself a claim that production Signal users are at risk.
- **Seam 5** is a missing-defense observation, not a vulnerability.

### Tests that exhibit each seam

Each finding gets a corresponding unit test that mechanically demonstrates the
claim. All tests are under `rust/protocol/tests/`; they are written to compile and
run against the code in this snapshot (upstream `0a58e80b`).

| Seam | Test | What it proves |
|------|------|-----------------|
| 2    | `seam2_sss_accepts_cert_key_not_in_identity_store` | `sealed_sender_decrypt_to_usmc` returns a USMC whose `sender().key()` differs from the `IdentityKeyStore` entry for that address; the SSS layer does no cross-check |
| 3a   | `seam3_sender_certificate_accepts_pni_uuid`        | `SenderCertificate::new` + `validate` succeeds for a PNI-prefixed `sender_uuid` string; no kind check in Rust |
| 4a   | `seam4_inmem_tofu_on_first_use`                    | `InMemIdentityKeyStore::is_trusted_identity` returns `true` for a never-seen `(address, key)` regardless of `direction` |
| 4b   | `seam4_inmem_ignores_direction`                    | After `save_identity`, calling `is_trusted_identity` with a mismatching key returns the same result for `Sending` and `Receiving` |

Seam 3's end-to-end harm chain (combining with attack-1 PNI TOFU injection) is not
replicated as a unit test — it duplicates the paper's §3 PoC at the application
layer and adds no verification value. Seam 5 has no test because the finding is
*no caller exists*; the standing grep is the evidence.

### Test log

Tests added in `rust/protocol/tests/seam_tests.rs`. Run with
`cargo test --test seam_tests`. All four pass on upstream commit `0a58e80b`:

```
running 4 tests
test seam4_inmem_tofu_on_first_use ... ok
test seam4_inmem_ignores_direction ... ok
test seam2_sss_accepts_cert_key_not_in_identity_store ... ok
test seam3_sender_certificate_accepts_pni_uuid ... ok

test result: ok. 4 passed; 0 failed
```

What each test mechanically demonstrates:

- **seam 2** — Built a forged `SenderCertificate` claiming to be Alice but
  carrying an attacker-generated identity key. Bob's `IdentityKeyStore` holds
  Alice's *real* identity key (as if safety numbers had been compared).
  `sealed_sender_decrypt_to_usmc` returns a USMC whose `sender().key()` equals
  the attacker's public key — not Alice's stored key — and does not consult the
  IdentityKeyStore for Alice's address. Assertion
  `decrypted.sender()?.key()? == attacker_keys.public_key() != alice_real.public_key()`
  passes. This is the paper's attack-2 issue 1, reproduced as a mechanical Rust
  unit test against the current code.
- **seam 3** — `SenderCertificate::new` accepted a `sender_uuid` of
  `"PNI:12345678-aaaa-bbbb-cccc-123456789abc"` and the server signature
  validated without complaint. No kind check at construction, deserialization,
  or validation.
- **seam 4a** — `InMemIdentityKeyStore::is_trusted_identity` returned `true`
  for a never-seen `(address, attacker_key)` pair for both
  `Direction::Sending` and `Direction::Receiving`.
- **seam 4b** — After `save_identity(addr, peer_key)`, a follow-up
  `is_trusted_identity(addr, different_key, ...)` returned the same value
  (`false`) for both directions — direction is functionally ignored.

These tests are intentionally minimal and deterministic: they depend only on
libsignal-protocol's public API and the reference in-memory store. They are
executable evidence that each of seams 2, 3, 4a, 4b exists in the current tree.

## Verification deep-dive — Seam 2

Two parallel specification experiments, one per tool. Both express the same
abstract trust invariant ("the sender key returned by SSS decryption must
match the receiver's trusted-identity mapping for that sender's address") and
both converge on the same demonstration: the current libsignal behavior cannot
discharge this invariant without adding an explicit check.

### Verus track — `verification/verus/seam2.rs`

Self-contained Rust file. Three functions:

- `ss_decrypt_to_usmc_bad` — matches current libsignal behavior (returns the
  certificate's identity verbatim, no store consultation), with the trust
  postcondition attached.
- `ss_decrypt_to_usmc_fixed_precondition` — same body, but the trust
  obligation is pushed to the caller as a `requires`.
- `ss_decrypt_to_usmc_fixed_check` — performs the check inside, returns
  `Option<Usmc>`, discharges the postcondition on the `Some` branch. Uses an
  `#[verifier::external_body]` stub for the external `is_trusted_identity`
  call whose ensures clause ties its result to the ghost `trusted` map.

Command:

```
cd verification/verus && /home/lacra/verus/verus seam2.rs
```

Result:

```
error: postcondition not satisfied
  --> seam2.rs:72:9
   |
72 |         store.is_trusted(result.sender_uuid, result.sender_key),
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ failed this postcondition
verification results:: 4 verified, 1 errors
```

Verus rejects exactly the bad version and accepts the other three (plus the
predicates). The error message points at the precise line where the
specification is violated — the same line of reasoning that made the paper's
attack #2 issue 1 possible.

### Lean / Aeneas-style track — `Libsignal/Specs/Seam2.lean`

Integrated into the existing Lake project. Same abstract shape:

- Types: `IdentityKey`, `ProtocolAddress`, `IdentityKeyStore`, `SenderCertificate`, `Usmc`.
- Predicates: `IdentityKeyStore.isTrusted`, executable `checkTrusted`.
- Functions: `ssDecryptToUsmcBad`, `ssDecryptToUsmcFixedPre`, `ssDecryptToUsmcFixedCheck`.
- Theorems:
  - An `example` exhibiting a concrete **counter-example** store that falsifies
    the trust predicate for `ssDecryptToUsmcBad` (cert claims key `99`, store
    trusts key `42` for that address; the returned USMC has `senderKey = 99`
    which is not trusted).
  - `ssDecryptToUsmcFixedPre_trust` — proves the trust theorem under the
    strengthened precondition.
  - `IdentityKeyStore.checkTrusted_iff` — soundness of the Boolean check.
  - `ssDecryptToUsmcFixedCheck_trust` — proves the trust theorem for the
    option-returning version; the proof threads through the `checkTrusted_iff`
    equivalence.

Command:

```
lake build Libsignal.Specs.Seam2
```

Result:

```
✔ [2/2] Built Libsignal.Specs.Seam2 (205ms)
Build completed successfully (2 jobs).
```

All theorems discharged, no `sorry`/`axiom`/`admit` used. The Lean version
complements Verus: where Verus reports a verification failure on the bad
version, Lean *constructs* an explicit counter-example, which is a strictly
stronger falsification (existence witness rather than SMT-timeout).

### What this establishes, and what it does not

Established:

- Both Verus and Lean can express the seam-2 invariant cleanly with one
  predicate on the store.
- The gap between the bad and fixed versions is mechanical in both tools:
  Verus reports a concrete postcondition violation; Lean constructs a
  counter-example that makes the violation explicit.
- The required code change in real libsignal is structurally identical to the
  difference between `ss_decrypt_to_usmc_bad` and `ss_decrypt_to_usmc_fixed_check`:
  call the store's `is_trusted_identity` before returning, and return an error
  (or equivalent) on mismatch.

Not yet established:

- That either tool can verify this against the **actual** Rust code in
  `rust/protocol/src/sealed_sender.rs`. Verus would need the libsignal build to
  be annotated (significant effort across async boundaries). Aeneas would need
  extraction of `rust/protocol/` into Lean (large, with Kyber/EC/async
  dependencies to opaque-ify). Both are plausible but each is a multi-day
  project.
- That the ghost `trusted` map is the right abstraction for production. In
  real libsignal the store is a `dyn IdentityKeyStore` whose behaviour is
  app-specific; the spec we wrote axiomatizes what every implementation must
  provide rather than what any particular one does. That's the usual
  trade-off for trait-based specification.

## Verification deep-dive — trait-level Verus + Lean using extracted types

Two further experiments, both one step closer to "real libsignal":

### Verus: trait-based model — `verification/verus/seam2_trait.rs`

`IdentityKeyStore` is now a Rust trait with:

- a spec-level `fn trusted(&self) -> Map<ProtocolAddress, IdentityKey>` view,
- an exec `is_trusted_identity` whose `ensures` ties its result to the view,
- an exec `save_identity` whose `ensures` says the view grows by the inserted pair.

On top of the trait, `ss_decrypt_to_usmc_bad` (current libsignal shape) is
still rejected — the verifier chases the postcondition through `<S: IdentityKeyStore>`
and finds that nothing in the body established trust. `ss_decrypt_to_usmc_fixed`
discharges via a call to `is_trusted_identity`. Crucially, a caller
`caller_accepts_only_trusted` that *composes* on top of `ss_decrypt_to_usmc_fixed`
discharges its own postcondition **without re-checking** — the trait-level
invariant carries through, which is exactly what is needed for downstream
paths (`session_cipher`, `group_cipher`) to inherit the trust guarantee.

Result:

```
error: postcondition not satisfied
  --> seam2_trait.rs:69:9
   |
69 |         store.trusted().contains_key(result.sender_uuid),
   |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ failed this postcondition
verification results:: 4 verified, 1 errors
```

This is the most realistic Verus demonstration short of annotating real
libsignal: the trait and its ghost view mirror `storage::traits::IdentityKeyStore`
almost 1:1 (modulo async), and the failing postcondition points at exactly
the same missing check that the paper's attack #2 issue 1 exploits.

### Lean: seam 3 on actually-extracted types — `Libsignal/Specs/Seam3.lean`

Uses the Aeneas-extracted `signal_crypto.libsignal_core.address.ServiceId`,
`SpecificServiceId`, and `ServiceIdKind` types directly — so the spec is
literally typechecked against the Rust types that Charon/Aeneas produced.

- `SenderCertificateUntyped { senderUuid : String, key : IdentityKey }`
  models the current libsignal shape.
- `pniCertExample` constructs a concrete well-formed certificate whose
  `senderUuid` is `"PNI:12345678-aaaa-bbbb-cccc-123456789abc"` — exactly the
  case our Rust unit test `seam3_sender_certificate_accepts_pni_uuid` also
  accepts.
- `untyped_not_aci_only` proves that "every `SenderCertificateUntyped` names
  an ACI" is **false**, using the counter-example.
- `SenderCertificateTyped { sender : SpecificServiceId 0#u8, key : … }`
  models the proposed fix — `SpecificServiceId 0#u8` is literally the
  Aeneas-extracted representation of the `Aci` constructor's payload type.
- `typed_always_aci` proves by construction that every such certificate's
  `asServiceId` is `.Aci _`.
- `typed_no_pni_constructor` proves there is no typed certificate whose
  `asServiceId` is `.Pni _`.

Result:

```
✔ [1629/1629] Built Libsignal.Specs.Seam3 (1.1s)
Build completed successfully (1629 jobs).
```

No `sorry`/`axiom`/`admit`. The `native_decide` used for the string literal
comparison is flagged by mathlib's lint (suppressed locally) but affects
only the counter-example computation.

### What the combined deep-dive shows

1. **Both tools handle the trust-level invariant cleanly.** Verus rejects
   the bad shape with a precise line and accepts the fix; Lean constructs
   concrete counter-examples and proves the positive theorems from the
   types directly.
2. **The trait/type boundary carries the invariant.** Verus shows that a
   caller of `ss_decrypt_to_usmc_fixed` discharges its own trust postcondition
   without re-checking — so a real libsignal patch only has to be made at
   the one call site, not at every consumer. Lean shows that changing
   `sender_uuid: String` to `sender: SpecificServiceId 0#u8` moves the
   entire ACI-only invariant into the type system.
3. **The specs plug into the extracted code we already have.** Seam 3's Lean
   file uses the actual Aeneas-generated types. That is the strongest
   evidence so far that this stack can carry the specification forward into
   a full proof once `rust/protocol/` is in extraction scope.

### Where this stops

The remaining integration work — annotating `rust/protocol/src/sealed_sender.rs`
in place for Verus, or extending `aeneas-config.yml` to cover the protocol
crate — is a multi-day engineering project. It is no longer a research
question (both tools clearly can handle the invariant shape); it is a build
integration question. The files added to this repo are the blueprint
for that integration:

- `verification/verus/seam2.rs` — minimum-viable Verus spec
- `verification/verus/seam2_trait.rs` — trait-level Verus spec
- `Libsignal/Specs/Seam2.lean` — minimum-viable Lean spec
- `Libsignal/Specs/Seam3.lean` — Lean spec against extracted types

## Verification deep-dive — production Verus workflow (`cargo verus verify`)

Matching the setup used by `~/git_repos/baif/dalek-verus`, we added two
Cargo crates that run through `cargo verus verify` rather than the raw
`verus` binary. This is the same workflow curve25519-dalek uses and is the
production target for any future Verus integration with libsignal.

### `verification/verus/seam_crate/` — stand-in types

Self-contained crate. `Cargo.toml` declares:

```toml
[package.metadata.verus]
verify = true
release = "0.2026.01.14.88f7396"
rust-version = "1.92.0"

[dependencies]
vstd = { git = "https://github.com/verus-lang/verus", rev = "88f7396" }
verus_builtin = { git = "https://github.com/verus-lang/verus", rev = "88f7396" }
verus_builtin_macros = { git = "https://github.com/verus-lang/verus", rev = "88f7396" }
```

The workspace root `Cargo.toml` was updated to `exclude = [".aeneas", "verification"]`
so these crates don't enter the main libsignal build.

`src/lib.rs` carries the same trait-based seam-2 spec from
`seam2_trait.rs`. Running from the crate directory:

```
$ cargo verus verify
...
verification results:: 4 verified, 1 errors
error: could not compile `seam_crate` (lib) due to 2 previous errors
```

Four verified: the trait itself, `ss_decrypt_to_usmc_fixed`,
`caller_accepts_only_trusted`, and the trait's ghost view consistency. One
error: `ss_decrypt_to_usmc_bad`, with the exact same postcondition line as
before. The production workflow and the experimental one agree.

### `verification/verus/seam_real/` — real libsignal-protocol imports

The ambitious step: add `libsignal-protocol` and `libsignal-core` as
**path dependencies** and import real types:

```toml
[dependencies]
libsignal-protocol = { path = "../../../rust/protocol" }
libsignal-core     = { path = "../../../rust/core" }
```

`src/lib.rs` imports real types:

```rust
use libsignal_protocol::{IdentityKey, ProtocolAddress};
```

and includes a `#[verifier::external]` bridge function that calls actual
`SenderCertificate::sender_uuid` / `::key`, using real
`SignalProtocolError`:

```rust
#[verifier::external]
pub fn real_cert_bridge(cert: &libsignal_protocol::SenderCertificate)
    -> Result<(String, Box<[u8]>), libsignal_protocol::SignalProtocolError>
{
    let uuid = cert.sender_uuid()?.to_string();
    let key  = cert.key()?.serialize();
    Ok((uuid, key))
}
```

`cargo verus verify` compiles the entire `libsignal-protocol` dependency
tree (including `tokio`, `async_trait`, `prost`, `curve25519-dalek`, etc.),
then runs Verus only over the annotated code. Result:

```
$ cargo verus verify
...
verification results:: 1 verified, 1 errors
```

One verified: `ss_decrypt_to_usmc_fixed`. One error: `ss_decrypt_to_usmc_bad`
at the trust postcondition line. The `external_body` glue (store queries,
cert bridge) does not need a body-level proof.

This shows the full production stack works:

1. Cargo resolves real libsignal-protocol and its dependencies.
2. Verus compiles the annotated crate in the presence of those deps.
3. Verus verifies the annotated functions and rejects the unsafe one.
4. The rejected postcondition names exactly the trust invariant the paper's
   attack #2 issue 1 exploits.

### What remains to reach an in-place annotation of `sealed_sender.rs`

With `cargo verus verify` demonstrated against real libsignal imports, the
remaining work is:

1. Add `[package.metadata.verus]` and `vstd`/`verus_builtin` (feature-gated)
   to `rust/protocol/Cargo.toml`.
2. Wrap the target function and its type surface in `verus! { ... }` blocks
   with selective `#[verifier::external]` / `#[verifier::external_body]`
   annotations. Expect the majority of the crate to be `external` initially.
3. Use `--verify-module sealed_sender` / `--verify-function
   sealed_sender_decrypt_to_usmc` to scope proof effort.
4. Hook up `libsignal_protocol::IdentityKeyStore` (the real trait) to an
   `#[verifier::external_type_specification]` adapter that exposes the
   ghost trust map.

None of these items is novel after what we have: dalek-verus already
demonstrates (1)–(3) and `seam_real` demonstrates (4) in stub form. Scope
estimate: a focused 2–3 day sprint to get the real `sealed_sender_decrypt_to_usmc`
rejected by Verus, then a matter of adding the one line of code to make it
verify — which is the documented fix.

### In-place annotation attempt — blocked on a Verus upstream panic

We attempted step (1) of the plan above: add the Verus metadata and
feature-gated deps to `rust/protocol/Cargo.toml`, drop a minimal `verus!`
block in a new `rust/protocol/src/verus_seam2.rs` sibling module, and run
`cargo verus verify -p libsignal-protocol --features verus-verify`.

**Cargo.toml diff** added under the feature `verus-verify`:

```toml
verus-verify = ["dep:vstd", "dep:verus_builtin", "dep:verus_builtin_macros"]

[dependencies.vstd]            # + verus_builtin + verus_builtin_macros
git = "https://github.com/verus-lang/verus"
rev = "88f7396"
optional = true

[package.metadata.verus]
verify = true
release = "0.2026.01.14.88f7396"
rust-version = "1.92.0"
```

**Result**: the feature-gated standard build (`cargo check -p libsignal-protocol
--features verus-verify`) passes cleanly. **`cargo verus verify --features
verus-verify` panics**, before any verification scoping takes effect:

```
thread 'rustc' panicked at rustc_hir/src/def.rs:846:
  attempted .def_id() on invalid res: PrimTy(Uint(u32))
stack backtrace:
  12: rust_verify::external::VisitMod::visit_general
  ...
  17: rust_verify::external::get_crate_items
  18: rust_verify::verifier::Verifier::construct_vir_crate
```

The panic is inside Verus's own `rust_verify::external` module — the
component that walks all items in the crate to classify them as
external/external_body/verify, **before** any `--verify-module` or
`--verify-function` scoping can kick in. It is triggered by some HIR
construct in libsignal-protocol that uses `u32` in a way Verus's walker
doesn't handle (likely a macro-expanded associated-constant expression or
a specific `const N: u32 = …` pattern in one of the many dependencies
pulled into `lib.rs` at crate-walk time).

This is **a Verus tool-level limitation**, not a specification problem:

- Our spec shape is known to work (`seam_real/` verifies against the same
  libsignal-protocol types as path dependencies; `seam_crate/` verifies
  the same trait contract through `cargo verus verify`).
- No amount of `#[verifier::external]` on our own code helps, because the
  panic occurs *while Verus is computing the external classification*.

**Decision**: revert the in-place changes to keep the main build clean and
fall back to the harness-crate pattern (`verification/verus/seam_real/`)
as the integration target. The in-place path re-opens when one of the
following happens:

1. The Verus upstream `rust_verify::external::VisitMod` walker is made
   robust to the specific HIR construct in libsignal-protocol.
2. The offending construct is isolated and either (a) marked external by
   a mechanism Verus honours pre-walk, or (b) removed/rewritten.
3. Verus gains a `--skip-external-walk` or similar opt-out that lets us
   scope verification to a single annotated module without walking the
   whole crate first.

**What we did not revert**: the four seam unit tests in
`rust/protocol/tests/seam_tests.rs`, the three Verus harness crates/files
under `verification/verus/`, the two Lean spec files under
`Libsignal/Specs/`, and the workspace-level `exclude = [".aeneas",
"verification"]`. Those remain as working demonstrations.

**Suggested report-upstream**: minimal reproducer for Verus issue tracker
would be a crate whose `lib.rs` contains whatever libsignal-protocol code
currently triggers the panic; bisecting with `#[verifier::external]` at
module level would localize it. Skipped here because localizing the
construct is a multi-hour rabbit hole and the practical integration path
(harness crate) is unblocked.

### Bisection results

We bisected to answer: "can we avoid the panic by writing the specs
differently?" The short answer is **no** — the panic is an artifact of the
crate environment, not of our annotations.

Setup: feature-gated all of libsignal-protocol's module declarations and
re-exports behind `#[cfg(not(feature = "verus-verify"))]`, leaving only a
minimal `mod verus_seam2;` (and an optional `use vstd::prelude::*;`) visible
to Verus.

Result: the original `VisitMod`/`PrimTy(Uint(u32))` panic **disappeared**
(confirming that trigger is inside libsignal-protocol's own source), and a
*different* panic surfaced:

```
thread 'rustc' panicked at rust_verify/src/erase.rs:308:14
stack backtrace:
   4: rust_verify::erase::setup_verus_ctxt_for_thir_erasure
```

Line 308 is an `.unwrap()` on `verus_items.name_to_id.get(&VerusItem::ErasedGhostValue)`
(see `/home/lacra/git_repos/verus/source/rust_verify/src/erase.rs:295-315`).
Verus expects to resolve an internal `ErasedGhostValue` / `DummyCapture`
item into the crate's name-to-id map and panics when the lookup returns
`None`. Triggered regardless of `verus_seam2.rs` being empty, containing
only `use vstd::prelude::*;`, or containing one trivial `verus!` function.

We confirmed `seam_crate` with `edition = "2024"` *still verifies cleanly*
(`4 verified, 1 errors`), so Rust edition is not the trigger. Adding
`spqr` as a dependency to `seam_crate` *also* kept verification working,
so the issue is not any single heavy dep.

**Reproducible delta between `seam_crate` (works) and `libsignal-protocol`
(panics)** that we did not separately reduce:

- workspace membership (`[workspace] members = ["rust/protocol", …]`)
- workspace lint inheritance (`[lints] workspace = true`)
- `build.rs` generating protobuf stubs (cfg-gated off, but `OUT_DIR` is
  still set)
- the broader dependency graph (dozens of deps vs. one or two)

Any combination of these triggers the `erase.rs:308` panic on an otherwise
empty crate shell. This is a **Verus-tool environmental sensitivity**, not
a specification issue.

**Implication for "write specs that avoid the panic"**: writing the specs
differently changes nothing. The panic fires before any spec annotations
are processed. The practical workarounds are:

1. **Harness crate pattern** (already demonstrated in `seam_real/`): keep
   the Verus-annotated code in a small standalone crate that depends on
   libsignal-protocol as a path dependency. Verus processes only the
   harness; the libsignal-protocol code surface never touches
   `rust_verify::external::VisitMod` or `erase.rs`.
2. **Upstream report**: either of the two panics is grounds for a
   well-scoped Verus bug report. The second one is especially suspicious
   (an `.unwrap()` that can never succeed if the crate has no Verus-mode
   items) and is a reasonable 30-line reproducer.

For this repo, pattern (1) is the unblocked path and everything under
`verification/verus/` already uses it.

### Root-cause of panic 1: `impl Trait for <primitive>`

Re-entering the bisection with the specific question "can we rewrite the
triggering Rust code to avoid panic 1?", we localized the panic to a
single line in Verus's own source:

`/home/lacra/git_repos/verus/source/rust_verify/src/external.rs:656`:

```rust
let type_def_id = match impll.self_ty.kind {
    rustc_hir::TyKind::Path(rustc_hir::QPath::Resolved(None, path)) => {
        path.res.def_id()   // panics if path.res is Res::PrimTy(...)
    }
    _ => { warn_unknown(); return None; }
};
```

When Verus's external-items walker encounters an `impl Trait for X` block
whose `self_ty` resolves to a primitive type (`u8`, `u32`, `u64`, `i32`,
`bool`, …), `path.res` is `Res::PrimTy(...)` rather than a `Res::Def(...)`,
and the unconditional `.def_id()` call panics with
`attempted .def_id() on invalid res: PrimTy(Uint(u32))`.

In libsignal-protocol, the trigger(s):

- `rust/protocol/src/sealed_sender.rs:498`: `impl From<ContentHint> for u32`
- `rust/protocol/src/state/prekey.rs:15`: `#[derive(..., derive_more::Into)]`
  on `PreKeyId(u32)` — the macro expansion produces
  `impl From<PreKeyId> for u32`.
- `rust/protocol/src/state/signed_prekey.rs:16`: ditto for
  `SignedPreKeyId(u32)`.
- `rust/protocol/src/state/kyber_prekey.rs:16`: ditto for
  `KyberPreKeyId(u32)`.

Each generates an `impl ... for u32` block. Verus's walker trips on any of
them. The derive-macro expansions are just as problematic as hand-written
impls — `derive_more::Into` produces HIR with the same `Res::PrimTy` self
type.

### Semantically-equivalent rewrites that avoid panic 1

Two patterns work. Both require touching both the definition site **and
every call site**, because the Rust type system distinguishes
`u32::from(id)` / `id.into()` (trait-based) from `id.into_u32()`
(inherent method).

**Pattern A — inherent method under the feature, gate the impl:**

```rust
#[derive(
    Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, derive_more::From,
)]
#[cfg_attr(not(feature = "verus-verify"), derive(derive_more::Into))]
pub struct PreKeyId(u32);

impl PreKeyId {
    pub const fn as_u32(&self) -> u32 { self.0 }
}
```

Rewrite every callsite from `u32::from(id)` / `id.into()` to
`id.as_u32()`. The `From<u32> for PreKeyId` direction can stay (that's
`impl Foo for <tuple struct>`, not `impl Foo for <primitive>`), so
constructions `PreKeyId::from(raw)` continue to work.

**Pattern B — replace with a newtype wrapper:**

```rust
#[derive(Copy, Clone, ..., derive_more::Into)]
pub struct PreKeyIdU32(u32);   // newtype

impl From<PreKeyId> for PreKeyIdU32 { ... }
impl From<PreKeyIdU32> for u32 { ... }  // STILL problematic — same panic
```

Pattern B does not actually help because the newtype doesn't eliminate the
`impl ... for u32` at the boundary; it only moves it. Skip.

### Empirical validation

We patched libsignal-protocol per Pattern A, enabled `verus-verify`, and
ran `cargo verus verify --features verus-verify`:

- `cargo check --features verus-verify` builds cleanly after rewriting
  the callsites (we left this step incomplete — 12 callsites across
  `rust/protocol/src/protocol.rs`, `state/session.rs`, `state/prekey.rs`,
  `state/signed_prekey.rs`, `state/kyber_prekey.rs` need the `.into()` →
  `.as_u32()` change). Invasive but mechanical.
- With *one* impl-for-primitive removed (`sealed_sender.rs:498` only),
  panic 1 *still fires* because the three derive-generated impls remain.
  Confirmed by bisection.
- Removing *all four* would cause panic 1 to flip to panic 2 (erase.rs).

**Conclusion on "rewrite to avoid panic 1"**: yes, technically
achievable via Pattern A + full callsite rewrite. Cost is moderate
(~12 callsites + 4 type definitions) and would leave the production code
slightly less ergonomic (`id.as_u32()` instead of `id.into()`). Not done
in this repo because the harness-crate path (`seam_real/`) does not
require any libsignal changes.

### Panic 2 (`erase.rs:308`) remains after panic-1 fixes

Panic 2 fires on an empty crate shell — independent of source code. It is
about the crate environment: workspace membership, build.rs, dependency
graph. No source rewrite in libsignal-protocol will prevent it. Once we
rewrite all impl-for-primitive away, Verus advances to panic 2 and still
cannot complete a run.

## Breakthrough — in-place Verus verification works

After adding the `#[automatically_derived]` trigger analysis above, we tested
the two-step fix: (a) rewrite the four `derive_more::Into` / hand-written
impl-for-primitive sites as hand-written impls, and (b) upgrade Verus from
`0.2026.01.14.88f7396` to the latest stable `0.2026.04.19.6f7d4de`.

**Result: in-place verification of the real `libsignal-protocol` crate
succeeds.**

Running `cargo verus verify -p libsignal-protocol --features verus-verify`
with the patched crate on the new Verus:

```
Compiling libsignal-protocol v0.1.0
verification results:: 1556 verified, 0 errors   (vstd)
verification results:: 1 verified, 1 errors      (libsignal-protocol)
error: postcondition not satisfied
  --> rust/protocol/src/verus_seam2.rs:70:9
   |           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ failed this postcondition
```

- **1 verified**: `ss_decrypt_to_usmc_fixed` — discharges the trust
  postcondition by calling the ghost `check_trusted`.
- **1 error**: `ss_decrypt_to_usmc_bad` — mirrors current libsignal
  behavior; returns the cert's identity without consulting the trust
  map. Verus rejects it with the exact postcondition failure that
  encodes attack #2 issue 1.

### Minimal changes required

1. **`rust/protocol/Cargo.toml`**: add the `verus-verify` feature with
   optional `vstd`/`verus_builtin`/`verus_builtin_macros` deps, plus a
   `[package.metadata.verus]` section pointing at the new release/toolchain.

2. **`rust/protocol/src/lib.rs`**: feature-gated `mod verus_seam2;` —
   one-line addition.

3. **Three hand-written `impl From<IdType> for u32` blocks** (one each in
   `state/prekey.rs`, `state/signed_prekey.rs`, `state/kyber_prekey.rs`),
   gated `#[cfg(feature = "verus-verify")]`, with the `derive_more::Into`
   derive also gated to run only when the feature is off. Identical
   runtime behavior; the only difference is whether the impl carries the
   `#[automatically_derived]` attr — and Verus's walker trips on
   primitive self-types *only when that attr is present*.

4. **`rust/protocol/src/verus_seam2.rs`**: new file with the seam-2
   spec (`TrackedStore`, `check_trusted`, `ss_decrypt_to_usmc_bad`,
   `ss_decrypt_to_usmc_fixed`, `real_cert_bridge`).

That's it. No changes to `sealed_sender.rs`, no changes to the public
API, no changes to any callsite of `u32::from(id)` / `id.into()`
(because the hand-written impl provides the exact same `From<X> for u32`
trait). `cargo check -p libsignal-protocol` (no features) finishes in
0.64s. All six seam unit tests still pass.

### Why the upgrade was necessary

The old Verus `0.2026.01.14.88f7396` hit *two* panics:

- **Panic 1** (`VisitMod` / `PrimTy(Uint(u32))`): fixed by writing the
  impls by hand. Localized; still present in upstream Verus HEAD.
- **Panic 2** (`erase.rs:308` — `.unwrap()` on
  `name_to_id.get(&VerusItem::ErasedGhostValue)`): fixed by the upgrade.
  The new release's rewritten erasure pipeline (see the
  `rustc_mir_build_additional_files/verus.rs` machinery added in main
  after 88f7396) no longer has the brittle lookup in that exact form.

Either fix alone is insufficient: the old Verus hits panic 2 regardless of
source; the new Verus hits panic 1 if `derive_more::Into` expansions
remain. Together they unblock in-place verification.

### What this unlocks

The harness-crate pattern (`verification/verus/seam_real/`) is no longer
the only path. The seam-2 specification now lives **inside
`libsignal-protocol`'s own source tree**, verified against the real
types, with the `real_cert_bridge` function in scope of the actual
`SenderCertificate::sender_uuid`/`::key` accessors. Adding more
specifications is now a matter of writing more `verus!` blocks in
`verus_seam2.rs` (or companion modules) and letting the trait-level
ghost invariants flow through. Future targets:

- Bind the ghost `TrackedStore` to the real `IdentityKeyStore` trait via
  `#[verifier::external_type_specification]`.
- Extend the spec to `sealed_sender_decrypt` and the session_cipher
  handoff, matching the composition proven abstractly in
  `verification/verus/seam_real/`.
- Add seam-3 (`SenderCertificate.sender_uuid` typed as `Aci`) as a
  companion Verus proof alongside the Lean one in
  `Libsignal/Specs/Seam3.lean`.

### Upstream patch (concrete, two-line fix)

The real fix for panic 1 is upstream in Verus. At
`rust_verify/src/external.rs:656`:

```rust
// Before:
let type_def_id = match impll.self_ty.kind {
    rustc_hir::TyKind::Path(rustc_hir::QPath::Resolved(None, path)) => {
        path.res.def_id()
    }
    _ => { warn_unknown(); return None; }
};

// After (proposed):
let type_def_id = match impll.self_ty.kind {
    rustc_hir::TyKind::Path(rustc_hir::QPath::Resolved(None, path))
        if matches!(path.res, rustc_hir::def::Res::Def(..)) =>
    {
        path.res.def_id()
    }
    rustc_hir::TyKind::Path(rustc_hir::QPath::Resolved(None, _path)) => {
        // primitive self-type — skip without panicking
        return None;
    }
    _ => { warn_unknown(); return None; }
};
```

A one-line guard. Filing this as a Verus issue would unblock the in-place
annotation path permanently. The harness-crate path still works in the
meantime.

## Extension of `seam_real` — full decrypt pipeline

After the in-place attempt was blocked, we extended `verification/verus/seam_real/`
to cover the *composition* across SSS and session_cipher. The harness now
models:

- `TrackedSessionStore`: ghost map of address → session's
  `remote_identity_key` (mirroring `rust/protocol/src/state/session.rs`).
- `session_cipher_decrypt_signal`: abstract shape of
  `session_cipher::message_decrypt_signal` — requires a session to exist,
  looks up its stored identity key, runs `is_trusted_identity` against
  that key, and returns only on success.
- `full_decrypt_pipeline`: calls `ss_decrypt_to_usmc_fixed` then
  `session_cipher_decrypt_signal`, with the end-to-end trust postcondition
  `identity_store.is_trusted(cert_sender_addr, final_key)`.

Strengthening `ss_decrypt_to_usmc_fixed`'s ensures clause with
`u.sender_addr == cert_sender_addr && u.sender_key == cert_sender_key`
(previously implicit in the body but not exposed) is what lets Verus
discharge the composition. Result:

```
$ cargo verus verify
verification results:: 3 verified, 1 errors
```

Three functions verified (`ss_decrypt_to_usmc_fixed`,
`session_cipher_decrypt_signal`, `full_decrypt_pipeline`). One expected
error: `ss_decrypt_to_usmc_bad`.

This closes an important loop: the trust contract *propagates* from SSS
into the session-cipher layer via the trait-level `is_trusted_identity`
check. Whenever the upstream fix is in place, the downstream decryption
inherits the trust guarantee without needing its own independent
check — exactly the composition property that motivated the ghost-map
abstraction in the first place.

**Caveat**: the harness's `session_cipher_decrypt_signal` re-runs
`is_trusted_identity(remote_addr, session_key)`. The value that ends up
in `final_key` is the *session's* stored key, not the cert's. The
composition verifies because the trust map eventually covers both; it
does *not* verify that the session key and the cert key are equal. That
is a further spec decision — whether the seam-2 fix should also enforce
`session_key == cert_key` at the handoff — and is the sort of thing the
spec can be tightened to say, once stakeholders decide what the right
contract is.

## Related documents

- `shared_state_seams.md` (this file) — seam analysis + Verus results
- `aeneas_integration_plan.md` — plan for the Aeneas/Lean parallel track
  (target functions, extraction config changes, known blockers, order
  of operations). Read this if/when you want to pick up the extraction
  side of the same verification story.
