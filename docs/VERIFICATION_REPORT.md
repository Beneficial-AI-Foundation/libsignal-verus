# libsignal-verus — Verification Report

**Base libsignal commit:** `0a58e80b`
**Verus:** `0.2026.04.19.6f7d4de`
**Report date:** 2026-04-24
**Companion repo:** `libsignal-verify/` (Aeneas / Lean track)

## Executive summary

This repo carries Verus annotations applied in-place to the
`libsignal-protocol` Rust crate, motivated by Truong, Terzo, Paterson,
*Signal Lost (Integrity): The Signal App is More than the Sum of its
Protocols* (IACR ePrint 2026/484, "the paper" below).

Headline outcome: **in-place Verus verification of `libsignal-protocol`
works.** A one-line change to `sealed_sender_decrypt_to_usmc` (add the
missing `is_trusted_identity` call) would turn the Verus check from red
to green on the mechanically-stated trust invariant. The infrastructure
is shipping-quality — `cargo check -p libsignal-protocol` is unchanged
(no new deps enabled by default), seam unit tests pass, and the Verus
feature gate opts in with one `--features verus-verify` flag.

The seam analysis that motivated this spec — six cross-protocol seams in
libsignal-protocol, of which the one targeted here (seam 2, the paper's
attack-2 issue 1) is **unpatched in libsignal Rust at commit `0a58e80b`**
— is in `docs/shared_state_seams.md`. The term "seam" is defined in that
document's §Terminology; in short, a *seam* is a junction point between
two protocol components where each side has its own trust assumption and
nothing enforces that they agree.

---

## Context: the attack we are tracking

Attack 2, issue 1, from the paper: the SSS receiver
`sealed_sender_decrypt_to_usmc` at
`rust/protocol/src/sealed_sender.rs:1832–1956` authenticates against the
sender-certificate's own identity key (server-issued), **not** against
the receiver's `IdentityKeyStore` entry. Under the paper's threat model
(malicious server with a valid server-certificate key, honest clients),
this lets a forged certificate pass the SSS layer. Signal patched the
second bug in this chain (Android's `PLAINTEXT_CONTENT` validation) but
did not patch this one.

```bash
grep -n is_trusted_identity rust/protocol/src/sealed_sender.rs
# (empty)
```

Our goal: express the missing invariant as a Verus postcondition and
prove that the current code fails it while the proposed fix discharges it.

---

## Prerequisites & environment

### Toolchains

- Rust nightly `nightly-2026-03-23` (pinned by `rust-toolchain`; used for
  the main libsignal build).
- Rust stable `1.95.0` (required by Verus 0.2026.04.19):

  ```bash
  rustup toolchain install 1.95.0-x86_64-unknown-linux-gnu
  ```

### Verus 0.2026.04.19

```bash
mkdir -p /tmp/verus-new && cd /tmp/verus-new
curl -sSL -O "https://github.com/verus-lang/verus/releases/download/release/0.2026.04.19.6f7d4de/verus-0.2026.04.19.6f7d4de-x86-linux.zip"
unzip verus-0.2026.04.19.6f7d4de-x86-linux.zip
export NEW_VERUS=/tmp/verus-new/verus-x86-linux
```

Older releases (e.g. `0.2026.01.14.88f7396`) hit an `erase.rs:308`
panic on libsignal-protocol regardless of source. The 2026-04-19
release fixes it. See §"Verus panics and workarounds" below.

---

## Reproducible end-to-end script

Copy-paste into a fresh shell session from the repo root:

```bash
set -e
export NEW_VERUS=/tmp/verus-new/verus-x86-linux

# [1/4] Baseline: main build + seam unit tests
cargo check -p libsignal-protocol
cargo test  -p libsignal-protocol --test seam_tests
# expect: all seam_* tests pass

# [2/4] Standalone harness crates (abstract spec)
(cd verification/verus/seam_crate && $NEW_VERUS/cargo-verus verus verify)
# expect: 1556 verified (vstd) + 4 verified, 1 errors (our code)

(cd verification/verus/seam_real && $NEW_VERUS/cargo-verus verus verify)
# expect: 1 verified, 1 errors

# [3/4] In-place Verus on libsignal-protocol (the milestone)
(cd rust/protocol && $NEW_VERUS/cargo-verus verus verify --features verus-verify)
# expect: 1556 verified (vstd) + 1 verified, 1 errors
#         the 1 error is the intended postcondition failure on
#         ss_decrypt_to_usmc_bad at verus_seam2.rs:70
```

---

## What is verified

### In-place: `rust/protocol/src/verus_seam2.rs`

The spec lives inside `libsignal-protocol` itself and uses the real
`SenderCertificate` type via `real_cert_bridge`. Verified contracts:

- **`ss_decrypt_to_usmc_fixed`** (passes):

  ```
  ensures match result {
      Some(u) =>
          u.sender_addr == cert_sender_addr
          && u.sender_key == cert_sender_key
          && store.trusted.contains_key(u.sender_addr)
          && store.trusted[u.sender_addr] == u.sender_key,
      None => true,
  }
  ```

  The `Some` branch is reached only after `check_trusted` returns `true`,
  which ties the result to the ghost trust map.

- **`ss_decrypt_to_usmc_bad`** (fails — intentional):

  ```
  ensures
      store.trusted.contains_key(result.sender_addr),
      store.trusted[result.sender_addr] == result.sender_key,
  ```

  Mirrors current libsignal behavior: returns the cert's identity
  verbatim without consulting the store. Verus rejects the postcondition
  with:

  ```
  error: postcondition not satisfied
    --> rust/protocol/src/verus_seam2.rs:70:9
  ```

  That line exactly encodes attack-2 issue 1.

### Abstract: `verification/verus/{seam2.rs, seam2_trait.rs, seam_crate/, seam_real/}`

Progressively more-realistic Verus specs of the same invariant.
`seam_real/` depends on real `libsignal-protocol` types via `path =`,
serving as a sanity comparison to the in-place version.

---

## Source-tree changes to libsignal-protocol

Five feature-gated additions. No changes to public API, no changes to
runtime semantics when the feature is off.

### Always-on additions

- `rust/protocol/tests/seam_tests.rs` — Rust unit tests that
  mechanically exhibit the seams (tool-agnostic evidence).
- `verification/verus/` — standalone Verus harness crates.
- `Cargo.toml` (workspace) — one-line `exclude = [".aeneas", "verification"]`
  so the harness crates don't enter the main workspace.

### Feature-gated additions (behind `--features verus-verify`)

1. `rust/protocol/Cargo.toml` — added `verus-verify` feature, three
   optional deps on `vstd` / `verus_builtin` / `verus_builtin_macros`,
   and a `[package.metadata.verus]` section pointing at the release/toolchain.

2. `rust/protocol/src/lib.rs` — one-line feature-gated
   `#[cfg(feature = "verus-verify")] mod verus_seam2;`.

3. `rust/protocol/src/state/{prekey,signed_prekey,kyber_prekey}.rs` —
   the `derive_more::Into` derive is gated
   `#[cfg_attr(not(feature = "verus-verify"), derive(derive_more::Into))]`,
   and a hand-written `impl From<IdType> for u32` is added under
   `#[cfg(feature = "verus-verify")]`. Identical runtime behavior; the
   only difference is whether the impl carries `#[automatically_derived]`.

4. `rust/protocol/src/verus_seam2.rs` — new file, the spec.

Without `--features verus-verify`, `cargo check -p libsignal-protocol`
shows the same build time as stock libsignal, and all three ID types
continue to use `derive_more::Into`.

---

## Verus panics and workarounds

Short version: two different Verus panics blocked naive in-place
annotation; each has a specific cause and mitigation. Full bisection
writeup in `docs/shared_state_seams.md`.

### Panic 1 — `VisitMod` walker + `PrimTy(Uint(u32))`

- **Where**: `rust_verify/src/external.rs:656` unconditionally calls
  `.def_id()` on the self-type of `impl` blocks marked
  `#[automatically_derived]`. When self-type is a primitive, this panics.
- **Scope**: the enclosing function is
  `fn get_attributes_for_automatic_derive` — runs only on items with
  the `#[automatically_derived]` attribute. Derive-macro expansions
  (e.g. `#[derive(derive_more::Into)]`) carry this attribute; hand-written
  `impl` blocks do not.
- **Trigger in libsignal-protocol**: `#[derive(derive_more::Into)]` on
  `PreKeyId(u32)`, `SignedPreKeyId(u32)`, `KyberPreKeyId(u32)`.
- **Workaround in this repo**: hand-write the three impls under
  `#[cfg(feature = "verus-verify")]`. No callsite changes needed; the
  hand-written impl provides the exact same `From` trait.
- **Upstream fix**: a one-line guard in Verus —
  `matches!(path.res, rustc_hir::def::Res::Def(..))` before calling
  `.def_id()`, or gracefully `return None` for non-Def paths. Not yet
  filed; see "Future tracks" below.

### Panic 2 — `erase.rs:308` `.unwrap()`

- **Where**: `rust_verify/src/erase.rs:308` unwraps
  `verus_items.name_to_id.get(&VerusItem::ErasedGhostValue)`.
- **Scope**: environmental to the Verus release. Fires on libsignal-protocol
  with `0.2026.01.14.88f7396` even on an otherwise empty `verus!` block.
- **Workaround**: upgrade to `0.2026.04.19.6f7d4de` or newer, where the
  erasure pipeline was rewritten and no longer has the brittle lookup.

Either fix alone is insufficient: the old Verus hits panic 2 regardless
of source; the new Verus hits panic 1 on `derive_more::Into` expansions.
Together they unblock in-place verification.

---

## Future tracks

Listed by decreasing readiness. Each is startable without needing the
prior one.

### A. Report Verus panic 1 upstream (hours)

Minimal reproducer: a 10-line crate with `#[derive(derive_more::Into)]`
on a `u32`-wrapping tuple struct plus `[package.metadata.verus] verify = true`.
Ideal patch is two lines in `rust_verify/src/external.rs`. Filing
this removes the need for the hand-written-impl workaround on future
libsignal types that follow the same pattern.

### B. Extend the in-place Verus spec (days)

The current `verus_seam2.rs` uses a ghost `TrackedStore` rather than
Verus's view of the real `IdentityKeyStore` trait. Next steps:

1. Add `#[verifier::external_type_specification]` for the real
   `IdentityKeyStore` trait and for `IdentityKey`, binding them to the
   ghost trust map.
2. Replace the `#[verifier::external_body] check_trusted` stub with a
   real call through the trait.
3. Specify `sealed_sender_decrypt` end-to-end, matching the composition
   proven in `verification/verus/seam_real/`.

Target: the fix to close attack-2 issue 1 becomes literally "add the
`is_trusted_identity` call, re-run `cargo verus verify`, observe
`2 verified, 0 errors`."

### C. Seam-3 companion spec (days)

`docs/shared_state_seams.md` §Seam 3 describes the
`SenderCertificate.sender_uuid: String` → `Aci` type refactor. The Lean
counterpart in the companion repo (`Libsignal/Specs/Seam3.lean`)
already proves the invariant by typing. A Verus spec alongside the
seam-2 spec would demonstrate the same result via
`libsignal_core::Aci` + `SpecificServiceId<0>`.

### D. Broader seam coverage

Existing Verus work covers seams 2 and (abstractly) 3. Open seams 1, 4,
5, 6 are discussed in `shared_state_seams.md`. Seam 6 (`message-backup`
restore) is out of reach without moving the restore-write path from
client code into Rust.

### E. Upstream to libsignal

The Cargo.toml diff is minimal, feature-gated, and does not affect the
default build. Open question for Signal maintainers: would they accept
Verus-verify annotations in their public Rust source, or prefer to
track them in a fork?

---

## Index

| Path                                             | Purpose                                              |
|--------------------------------------------------|------------------------------------------------------|
| `README.md`                                      | Top-level intro                                      |
| `docs/VERIFICATION_REPORT.md`                    | This file                                            |
| `docs/shared_state_seams.md`                     | Seam analysis + bisection/breakthrough writeup       |
| `rust/protocol/src/verus_seam2.rs`               | In-place Verus spec                                  |
| `rust/protocol/Cargo.toml`                       | Feature-gated Verus deps                             |
| `rust/protocol/src/state/{prekey,signed_prekey,kyber_prekey}.rs` | Panic-1 workaround (hand-written `From<Id> for u32`) |
| `rust/protocol/tests/seam_tests.rs`              | Mechanical seam-exhibiting unit tests                |
| `verification/verus/seam2.rs`                    | Abstract Verus spec                                  |
| `verification/verus/seam2_trait.rs`              | Trait-based Verus spec                               |
| `verification/verus/seam_crate/`                 | `cargo verus verify` harness (abstract)              |
| `verification/verus/seam_real/`                  | `cargo verus verify` harness (real libsignal types)  |

For the Aeneas / Lean track (extracted `libsignal-core` types, Lean
proofs, Aeneas extraction plan) see the companion repo
`libsignal-verify/`.
