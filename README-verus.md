# libsignal-verus

Verus-verified specification of selected `libsignal-protocol` invariants.

Base: [`signalapp/libsignal`](https://github.com/signalapp/libsignal) at
commit `0a58e80b`. Verus-specific patches and harness code applied in-place.

## Status

- **In-place verification works.** `cargo verus verify -p libsignal-protocol --features verus-verify`
  checks a specification of the missing identity-key cross-check in
  `sealed_sender_decrypt_to_usmc` (the paper's attack-2 issue 1) directly
  against the real libsignal-protocol crate.
- Current spec: 1 verified / 1 errors. The error is an intentional
  postcondition failure on `ss_decrypt_to_usmc_bad`, which mirrors
  current libsignal behavior; the companion `ss_decrypt_to_usmc_fixed`
  verifies cleanly.
- Normal builds are unaffected: `cargo check -p libsignal-protocol`
  does not pull in Verus dependencies unless `--features verus-verify`
  is passed.

## Companion repo

The Aeneas/Lean track lives in the sibling directory `libsignal-verify/`,
which hosts the Aeneas extraction config, Lean spec files
(`Libsignal/Specs/Seam2.lean`, `Seam3.lean`), and the broader
shared-state-seam analysis.

## Quick start

```bash
# 1. Install toolchains once
rustup toolchain install 1.95.0-x86_64-unknown-linux-gnu

mkdir -p /tmp/verus-new && cd /tmp/verus-new
curl -sSL -O "https://github.com/verus-lang/verus/releases/download/release/0.2026.04.19.6f7d4de/verus-0.2026.04.19.6f7d4de-x86-linux.zip"
unzip verus-0.2026.04.19.6f7d4de-x86-linux.zip
export NEW_VERUS=/tmp/verus-new/verus-x86-linux

# 2. Sanity: baseline build + seam tests
cd /path/to/libsignal-verus
cargo check -p libsignal-protocol
cargo test  -p libsignal-protocol --test seam_tests

# 3. In-place Verus verification of libsignal-protocol
(cd rust/protocol && $NEW_VERUS/cargo-verus verus verify --features verus-verify)
# expect: 1556 verified (vstd) + 1 verified, 1 errors (ours)

# 4. Standalone harness crates (optional sanity)
(cd verification/verus/seam_crate && $NEW_VERUS/cargo-verus verus verify)
(cd verification/verus/seam_real && $NEW_VERUS/cargo-verus verus verify)
```

Full reproducer and design notes: `docs/VERIFICATION_REPORT.md`.

## What is here

| Path                                         | Purpose                                              |
|----------------------------------------------|------------------------------------------------------|
| `rust/`                                       | Full libsignal Rust workspace (base `0a58e80b`) with Verus patches |
| `rust/protocol/src/verus_seam2.rs`           | In-place Verus seam-2 specification                  |
| `rust/protocol/Cargo.toml`                   | Feature-gated `verus-verify` + optional vstd deps    |
| `rust/protocol/src/state/*.rs`               | Hand-written `From<IdType> for u32` (panic-1 workaround) |
| `rust/protocol/tests/seam_tests.rs`          | Mechanical seam-exhibiting unit tests                |
| `verification/verus/seam2.rs`                | Minimum-viable abstract Verus spec                   |
| `verification/verus/seam2_trait.rs`          | Trait-based Verus spec                               |
| `verification/verus/seam_crate/`             | `cargo verus verify` harness with abstract types     |
| `verification/verus/seam_real/`              | `cargo verus verify` harness depending on real libsignal types |
| `docs/VERIFICATION_REPORT.md`                | Self-contained overview + reproducer                 |
| `docs/shared_state_seams.md`                 | Seam analysis + bisection/breakthrough writeup       |

## License

Base libsignal source: AGPL-3.0-only (Signal Messenger LLC). Verus
harness and spec files under the same license. See `LICENSE`.
