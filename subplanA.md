# Subplan A — Attested Ingress & Node Policy (Claude‑Optimized Scaffolding)

> **Goal.** Keep the baseline **batched‑threshold encryption** protocol exactly as in the paper/repo—same ciphertext format, same FK20 batch KZG openings, same one‑time DKG/CRS setup—and add an **optional, policy‑gated fast‑path** so validators can **skip per‑ciphertext proof verification** when a whitelisted TEE (“ingress”) has already verified the same relation and returned an attestation. If attestation is absent or untrusted, nodes fall back to the current cryptographic verification. This targets the dominant cost on the validator’s critical path (≈ **99%** of BatchDec time at realistic batch sizes), while preserving pending‑transaction privacy and the paper’s O(1) per‑party decryption broadcast (≈ **48 B**). :contentReference[oaicite:0]{index=0}  
>
> - **Baseline facts to preserve:** one‑time DKG + powers‑of‑τ CRS, BLS12‑381/arkworks, roots‑of‑unity domain, encryption ≈ **8.5 ms** and ciphertext ≈ **498 B**, BatchDec communication independent of B, FK20 O(B log B) openings, and **no per‑epoch setup**. (See **Fig. 2** and **Section 6**, esp. **Table 2**.) :contentReference[oaicite:1]{index=1}  
> - **Hybrid intent:** ingress TEEs act only as **verifiers/attestors** (not decrypters), binding the same well‑formedness relation + anti‑copy checks the paper requires (bind `(x̂, S, ct1..ct4, eid)`, prevent `(x̂, H(S))` reuse per epoch), with clean fallback to the pure cryptographic path—this mirrors the **HbTPKE‑TEE** ingress design. :contentReference[oaicite:2]{index=2}

---

## Do this in order (chronological)

1. **Refactor**: expose the *ciphertext‑validity relation* used by `Ciphertext::verify` into a shared helper (no behavior change).  
2. **Envelope & Acceptance Policy**: introduce `Envelope{eid, ct, att?}` and a gate that prefers **attested fast‑path** then falls back to **crypto verify**.  
3. **Ingress service (dev stub)**: a separate bin that calls the same relation, enforces per‑epoch anti‑copy, and **signs** an attested message.  
4. **Node integration**: add `partial_decrypt_envelope` that calls the acceptance gate, then proceeds unchanged.  
5. **Replay/anti‑copy**: per‑epoch Bloom filter over `(x̂, H(S))` in the ingress service; optional soft filter in node mempool. :contentReference[oaicite:3]{index=3}  
6. **Benches & tests**: show validator CPU saved by replacing proof‑verify with attestation‑verify at B∈{128, 512}; cover mixed (attested + pure‑crypto) batches. :contentReference[oaicite:4]{index=4}

---

## Workspace layout & feature flags

```
batch-threshold/          # existing library (crate name unchanged)
ingress-svc/              # new bin: dev "ingress" service (RA stub)
Cargo.toml                # workspace
```

**`batch-threshold/Cargo.toml` (add features):**
```toml
[features]
tee-ingress = []     # enable envelope & attestation policy types
dev-attest  = []     # dev-only verifier (accepts local signing key; no RA)
default = []         # default behavior = pure-crypto path
```

> Feature‑gate ensures **default build** stays identical to the paper’s implementation/results (encryption ≈ 8.5 ms; BatchDec dominated by proof‑verify; O(1) per‑party broadcast ≈ 48 B). :contentReference[oaicite:5]{index=5}

---

## 1) Refactor: expose the validity relation (no behavior change)

**New file:** `src/verification.rs`
```rust
//! Shared verification helpers used by validators and ingress.
//! MUST mirror the exact checks in `Ciphertext::verify` (Merlin transcript, equations, etc.).

use ark_ec::pairing::Pairing;
use crate::encryption::{Ciphertext, VerifyError};

pub fn verify_ciphertext_relation<E: Pairing>(
    ct: &Ciphertext<E>,
    htau: &E::G2,
    pk: &E::G2,
) -> Result<(), VerifyError> {
    // TODO: Move algebra/transcript checks from `Ciphertext::verify` here and return Ok on success.
    unimplemented!()
}
```

**Change:** in `src/encryption.rs`, make `Ciphertext::verify(..)` call `verification::verify_ciphertext_relation(..)` internally.

> This isolates the **same relation** validators must check and that the **ingress** TEE will check before attesting—matching the paper’s CCA/anti‑copy requirements (bind `S = g^s`, `tg = H(S)`, and protect against `(x̂, tg)` copy attacks via proof‑of‑knowledge). :contentReference[oaicite:6]{index=6}

---

## 2) Envelope & Acceptance Policy (library)

**New file:** `src/envelope.rs` *(behind `tee-ingress`)*

```rust
#![cfg(feature = "tee-ingress")]
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use crate::encryption::Ciphertext;

/// Public epoch identifier (bound into statements as in Fig. 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, CanonicalSerialize, CanonicalDeserialize)]
pub struct EpochId(pub u64);

/// Network envelope; `att = None` => pure-crypto verify path.
#[derive(Clone)]
pub struct Envelope<E: Pairing> {
    pub eid: EpochId,
    pub ct: Ciphertext<E>,
    pub att: Option<IngressAttestation>,
}

/// Attestation from ingress enclave: verifier can skip heavy proof checks if this verifies.
#[derive(Clone)]
pub struct IngressAttestation {
    pub sig: Vec<u8>,      // e.g., Ed25519 over AttestedMessage bytes
    pub quote: Vec<u8>,    // RA evidence (opaque in dev)
    pub ts_unix_ms: u64,   // freshness bound
    pub nonce: [u8; 16],   // replay-resistance
}

/// Canonical message the enclave signs (bind everything that matters).
#[derive(Clone)]
pub struct AttestedMessage {
    pub eid: EpochId,
    pub x_hat_bytes: [u8; 32],  // ct.x encoded canonically
    pub S_bytes: Vec<u8>,       // g^s encoded
    pub ct1: [u8; 32],
    pub ct2: Vec<u8>,
    pub ct3: Vec<u8>,
    pub ct4: Vec<u8>,
    pub ts_unix_ms: u64,
    pub nonce: [u8; 16],
}
```

**New file:** `src/attestation.rs` *(behind `tee-ingress`)*

```rust
#![cfg(feature = "tee-ingress")]
use ark_ec::pairing::Pairing;
use crate::envelope::{Envelope, IngressAttestation};

pub struct AcceptancePolicy {
    pub max_skew_ms: u64,
    pub allowlisted_measurements: Vec<Measurement>, // SGX/SEV measurements, etc.
    pub dev_mode: bool, // dev path: accept a local testing key (no real RA)
}

pub struct Measurement(pub Vec<u8>);

pub trait AttestationVerifier {
    fn verify_and_extract_pubkey(
        &self,
        quote: &[u8],
        pol: &AcceptancePolicy
    ) -> Result<AttestPubKey, AttestError>;
}

#[derive(Clone)]
pub struct AttestPubKey { pub alg: AttestSigAlg, pub key_bytes: Vec<u8> }

#[derive(Clone, Copy)]
pub enum AttestSigAlg { Ed25519, EcdsaP256 }

impl AttestPubKey {
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        // TODO: dispatch by alg; implement ed25519 verify in dev mode.
        unimplemented!()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AttestError {
    #[error("policy rejected RA evidence")] Policy,
    #[error("invalid signature")] InvalidSig,
    #[error("stale attestation")] Stale,
    #[error("internal")] Internal,
}

pub fn attested_message_bytes<E: Pairing>(env: &Envelope<E>) -> Vec<u8> {
    // eid || x̂ || S || ct1..ct4 || ts || nonce — canonical encodings
    // (optionally hash before signing)
    vec![]
}

/// Admission gate:
/// - If attestation verifies under policy => skip crypto proof-checks (fast-path).
/// - Else => run the full cryptographic `verify_ciphertext_relation` (fallback).
pub fn accept_or_verify<E: Pairing>(
    env: &Envelope<E>,
    pol: &AcceptancePolicy,
    av: &dyn AttestationVerifier,
    htau: &E::G2,
    pk: &E::G2,
) -> Result<(), VerifyGateError> {
    if let Some(att) = &env.att {
        let apub = av.verify_and_extract_pubkey(&att.quote, pol)?;
        let msg = attested_message_bytes(env);
        if apub.verify(&msg, &att.sig) && is_fresh(att.ts_unix_ms, pol) {
            return Ok(())
        }
        // fall through to crypto verify on failure
    }
    crate::verification::verify_ciphertext_relation(&env.ct, htau, pk)
        .map_err(VerifyGateError::Crypto)
}

fn is_fresh(_ts: u64, _pol: &AcceptancePolicy) -> bool {
    // TODO: wall-clock bound
    true
}

#[derive(thiserror::Error, Debug)]
pub enum VerifyGateError {
    #[error(transparent)]
    Crypto(#[from] crate::encryption::VerifyError),
    #[error(transparent)]
    Attest(#[from] AttestError),
}
```

> **Security equivalence.** Accepting a TEE attestation is **policy‑equivalent** to locally running the very same proof‑verification relation, provided RA is sound and the ingress also enforces the paper’s **non‑malleability/anti‑copy** checks (binding `(x̂, S, ct1..ct4, eid)` and rejecting duplicate `(x̂, H(S))` within an epoch). This matches the **HbTPKE‑TEE** ingress design and preserves the base scheme’s privacy/CCA2 properties with **graceful fallback** to the pure‑crypto path. :contentReference[oaicite:7]{index=7} :contentReference[oaicite:8]{index=8}

---

## 3) Ingress service (dev stub; separate crate)

**New crate:** `ingress-svc/` (runs *outside* a TEE in dev mode but behaves like it)

**`ingress-svc/Cargo.toml`**
```toml
[package]
name = "ingress-svc"
version = "0.1.0"
edition = "2021"

[dependencies]
batch-threshold = { path = "../batch-threshold", features = ["tee-ingress", "dev-attest"] }
blake3 = "1"
ed25519-dalek = "2"
anyhow = "1"
axum = "0.7"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
serde = { version = "1", features = ["derive"] }
serde_bytes = "0.11"
thiserror = "1"
```

**`ingress-svc/src/main.rs` (skeleton)**
```rust
//! DEV ingress: verifies the same relation and returns a signed attestation.
//! In production, wrap in RA-TLS and bind the key to the enclave measurement.

use anyhow::Result;
use axum::{routing::post, Json, Router};
use batch_threshold::{verification::verify_ciphertext_relation, envelope::*, attestation::*};
use ed25519_dalek::{SigningKey, Signer};

#[tokio::main]
async fn main() -> Result<()> {
    let sk = SigningKey::generate(&mut rand::rngs::OsRng); // dev-only
    let app = Router::new()
        .route("/attest", post(attest_handler))
        .with_state(sk);
    axum::Server::bind(&"0.0.0.0:8080".parse()?)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

#[derive(serde::Deserialize)]
struct AttestRequest {
    eid: u64,
    ct: serde_bytes::ByteBuf,
    pk: serde_bytes::ByteBuf,
    htau: serde_bytes::ByteBuf,
}

#[derive(serde::Serialize)]
struct AttestResponse {
    sig: serde_bytes::ByteBuf,
    quote: serde_bytes::ByteBuf, // empty in dev
    ts_unix_ms: u64,
    nonce: [u8;16],
}

async fn attest_handler(
    axum::extract::State(sk): axum::extract::State<SigningKey>,
    Json(_req): Json<AttestRequest>,
) -> Json<AttestResponse> {
    // 1) Deserialize ct, pk, htau; run `verify_ciphertext_relation(..)`
    // 2) Enforce per-epoch Bloom filter on (x̂, H(S)) to block copy/replay
    // 3) Build AttestedMessage bytes and sign with dev key
    // 4) Return signature and dev "quote"
    Json(AttestResponse { sig: serde_bytes::ByteBuf::from(vec![]), quote: serde_bytes::ByteBuf::from(vec![]), ts_unix_ms: 0, nonce: [0;16] })
}
```

**Replay filter (service‑side):** `ingress-svc/src/replay.rs`
```rust
use std::collections::HashMap;

pub struct EpochReplayFilter {
    // replace with a real Bloom filter if needed
    per_epoch: HashMap<u64, bloom::BloomFilter>,
}

impl EpochReplayFilter {
    pub fn new() -> Self { unimplemented!() }
    pub fn check_and_insert(&mut self, eid: u64, x_hat: &[u8], h_of_s: &[u8]) -> bool {
        // returns false on duplicate (x̂, H(S)) in this epoch
        unimplemented!()
    }
}
```

> The paper’s CCA2/non‑malleability notes (avoid `(x̂, tg)` copy; set `tg = H(S)` and prove knowledge of `s` with `S = g^s`) motivate the **per‑epoch anti‑copy** rule we enforce here. :contentReference[oaicite:9]{index=9}

---

## 4) Node integration (no API breakage)

Add an overload for envelopes; keep the original `partial_decrypt(..)` untouched for existing callers.

**Patch:** `src/decryption.rs`
```rust
use crate::verification::verify_ciphertext_relation;
#[cfg(feature = "tee-ingress")]
use crate::attestation::{AcceptancePolicy, AttestationVerifier, accept_or_verify};
#[cfg(feature = "tee-ingress")]
use crate::envelope::Envelope;

impl<E: ark_ec::pairing::Pairing> SecretKey<E> {
    // Existing API (unchanged behavior)
    pub fn partial_decrypt(
        &self,
        ct: &crate::encryption::Ciphertext<E>,
        hid: &E::G1,
        pk: &E::G2,
        crs: &CRS<E>,
    ) -> E::G1 {
        // ... current code path ...
        unimplemented!()
    }

    /// New helper: gate verification via attestation policy or fall back to crypto verify.
    #[cfg(feature = "tee-ingress")]
    pub fn partial_decrypt_envelope(
        &self,
        env: &Envelope<E>,
        hid: &E::G1,
        pk: &E::G2,
        crs: &CRS<E>,
        pol: &AcceptancePolicy,
        av: &dyn AttestationVerifier,
    ) -> E::G1 {
        accept_or_verify(env, pol, av, &crs.htau, pk).expect("verification failed");
        // proceed exactly as before using env.ct
        unimplemented!()
    }
}
```

> **Protocol invariants remain intact**: encrypt → (verify gate) → partial decrypt → combine (FK20 O(B log B) openings) with O(1) per‑party broadcast, **no per‑epoch setup**, and pending‑tx privacy. :contentReference[oaicite:10]{index=10}

---

## 5) Tests & benches (show the win)

**Example:** `examples/envelope_demo.rs`
```rust
//! Build with `--features tee-ingress,dev-attest`.
//! 1) Dealer setup; 2) encrypt a batch; 3) obtain `IngressAttestation` from dev service;
//! 4) wrap in `Envelope`; 5) partial_decrypt_envelope on t+1 parties; 6) combine & check.

fn main() {
    unimplemented!()
}
```

**Bench (new):** `benches/accept_gate.rs` — compare validator work for B∈{128,512}  
- **Baseline**: per‑ciphertext `verify_ciphertext_relation`.  
- **Attested**: verify Ed25519 signature + policy + replay filter (no heavy pairing checks).  

> The paper shows proof‑verify dominates BatchDec time (≈ 99% of Table 2 times). Your bench should reflect CPU savings when replacing these checks with attestation verification. :contentReference[oaicite:11]{index=11}

**Unit tests:**  
- `tests/attestation_gate.rs`: accepts valid dev signature; rejects bad sig/stale ts/invalid quote; mixed (some envelopes with attestation, some pure‑crypto) must decrypt correctly.  
- `tests/replay.rs`: same `(x̂, H(S))` within epoch → service refuses to attest. :contentReference[oaicite:12]{index=12}

---

## Developer switches

- **Node**: `--tee-ingress=off|dev|strict` (or env `TEE_INGRESS_MODE`)  
  - `off`: always run cryptographic verify (paper baseline).  
  - `dev`: accept dev key (no RA); for local testing.  
  - `strict`: require real RA verification and allowlisted measurements.
- **Service**: `--listen 0.0.0.0:8080`, `--dev-key <path>` (optional seed).  

> **Default build** (no features/flags) reproduces the paper’s baseline behavior and results (encryption ≈ 8.5 ms; ciphertext ≈ 498 B; BatchDec dominated by proof‑verify; per‑party broadcast ≈ 48 B). :contentReference[oaicite:13]{index=13}

---

## Definition of Done (Subplan A)

- [ ] `verification::verify_ciphertext_relation` factors out the checks; `Ciphertext::verify` delegates to it.  
- [ ] `Envelope`, `IngressAttestation`, `AcceptancePolicy`, `AttestationVerifier`, and `accept_or_verify` implemented (feature‑gated).  
- [ ] `SecretKey::partial_decrypt_envelope` added; original API intact.  
- [ ] `ingress-svc` dev server runs; signs `AttestedMessage`; enforces per‑epoch anti‑copy on `(x̂, H(S))`. :contentReference[oaicite:14]{index=14}  
- [ ] Example + benches compile with `--features tee-ingress,dev-attest`; bench shows validator CPU savings at B∈{128, 512}. :contentReference[oaicite:15]{index=15}  
- [ ] Tests cover policy, replay, mixed batches, and fallback.

---

## Why this is the right first step

- **Greatest impact on the critical path:** Per‑ciphertext proof verification dominates BatchDec time, so moving it behind a policy‑verified attestation yields the biggest practical speedup without touching encryption, aggregation, or FK20 open‑all logic. (See **Section 6**, **Table 2**, and the text noting ≈ 99% of time is proof‑verify.) :contentReference[oaicite:16]{index=16}  
- **Same security surface with graceful fallback:** The ingress attestation enforces the **same relation** and **anti‑copy** checks the paper requires (bind `(x̂, S, ct1..ct4, eid)`, prevent `(x̂, H(S))` reuse), with **strict fallback** to the cryptographic path on RA failure—exactly the **HbTPKE‑TEE** ingress policy. :contentReference[oaicite:17]{index=17}  
- **Preserves the paper’s advantages:** One‑time DKG, **no per‑epoch setup**, pending‑tx privacy, O(1) per‑party broadcast, and FK20 O(B log B) openings remain unchanged. :contentReference[oaicite:18]{index=18}

---

## Source anchors (for the implementer)

- **Core protocol & evaluation** — one‑time DKG + powers‑of‑τ CRS; no per‑epoch setup; cipher structure; `(x̂, S, tg=H(S))` with NIZK to stop copy‑attacks; FK20 O(B log B) openings; **Table 2** timings; ≈ **99%** BatchDec time in proof‑verify; ciphertext ≈ **498 B**; per‑party broadcast ≈ **48 B**. See **Fig. 2** and **Section 6**. :contentReference[oaicite:19]{index=19}  
- **HbTPKE‑TEE ingress** — accept attested `(eid, x̂, S, ct1..ct4, ts, nonce)` from whitelisted TEEs or fall back to SE‑NIZK checks; per‑epoch Bloom filter on `(x̂, H(S))`; strict fallback on RA failure. :contentReference[oaicite:20]{index=20}

