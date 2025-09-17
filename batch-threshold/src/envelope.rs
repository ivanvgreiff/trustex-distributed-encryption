#![cfg(feature = "tee-ingress")]
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::encryption::Ciphertext;

/// Epoch identifier used by the scheme (see Fig. 2 of the paper).
/// This is public metadata bound into the validity witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, CanonicalSerialize, CanonicalDeserialize)]
pub struct EpochId(pub u64);

/// Network envelope that carries either a TEE attestation or falls back to pure-crypto proof checks.
#[derive(Clone)]
pub struct Envelope<E: Pairing> {
    pub eid: EpochId,
    pub ct: Ciphertext<E>,
    pub att: Option<IngressAttestation>, // None => pure-crypto verify path
}

/// Attestation produced by the ingress enclave after checking the same relation as local verify.
/// The RA `quote` binds the enclave's signing key to a measured binary (allowlist-enforced).
#[derive(Clone)]
pub struct IngressAttestation {
    pub sig: Vec<u8>,      // e.g., Ed25519 signature over `AttestedMessage`
    pub quote: Vec<u8>,    // opaque RA evidence blob
    pub ts_unix_ms: u64,   // freshness bound
    pub nonce: [u8; 16],   // anti-replay within a time window
}

/// Message that the enclave signs. Bind *all* components needed to preclude copy/malleability:
/// (x̂, S, ct1..ct4, eid). The draft proposes preventing the copy-attack by binding (x̂, H(S))
/// and enforcing a per-epoch replay filter.
#[derive(Clone)]
pub struct AttestedMessage {
    pub eid: EpochId,
    pub x_hat_bytes: [u8; 32],  // canonical encoding of ct.x
    pub s_bytes: Vec<u8>,       // encoded group element g^s
    pub ct1: [u8; 32],
    pub ct2: Vec<u8>,
    pub ct3: Vec<u8>,
    pub ct4: Vec<u8>,
    pub ts_unix_ms: u64,
    pub nonce: [u8; 16],
}
