#![cfg(feature = "tee-ingress")]
use super::envelope::{Envelope};
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;
use blake3;

/// Policy describing which RA measurements are accepted, max age, etc.
pub struct AcceptancePolicy {
    pub max_skew_ms: u64,
    pub allowlisted_measurements: Vec<Measurement>, // e.g., SGX MRENCLAVE / SEV measurement
    pub dev_mode: bool, // if true, accept `dev-attest` signer
}

pub struct Measurement(pub Vec<u8>);

/// Trait to verify RA evidence and recover the enclave's attestation public key.
/// Provide two impls:
///   - DevAttestation (feature `dev-attest`): accepts a local testing key, no RA
///   - RealAttestation: perform RA verification (stub now; wire later)
pub trait AttestationVerifier {
    /// validate RA `quote`, check policy, and return an attestation pubkey (Ed25519, etc.)
    fn verify_and_extract_pubkey(&self, quote: &[u8], pol: &AcceptancePolicy) -> Result<AttestPubKey, AttestError>;
}

#[derive(Clone)]
pub struct AttestPubKey {
    pub alg: AttestSigAlg,
    pub key_bytes: Vec<u8>,
}

impl AttestPubKey {
    /// Verify signature over message bytes
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        match self.alg {
            AttestSigAlg::Ed25519 => {
                #[cfg(feature = "dev-attest")]
                {
                    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
                    
                    // Extract 32 bytes for public key
                    if self.key_bytes.len() < 32 || sig.len() != 64 {
                        return false;
                    }
                    
                    let key_bytes: [u8; 32] = match self.key_bytes[..32].try_into() {
                        Ok(bytes) => bytes,
                        Err(_) => return false,
                    };
                    
                    let sig_bytes: [u8; 64] = match sig.try_into() {
                        Ok(bytes) => bytes,
                        Err(_) => return false,
                    };
                    
                    // Try to create VerifyingKey and Signature
                    let vk = match VerifyingKey::from_bytes(&key_bytes) {
                        Ok(vk) => vk,
                        Err(_) => return false,
                    };
                    
                    // In ed25519-dalek 2.0, from_bytes might not return Result
                    let signature = Signature::from_bytes(&sig_bytes);
                    
                    vk.verify(msg, &signature).is_ok()
                }
                #[cfg(not(feature = "dev-attest"))]
                {
                    // Real Ed25519 verification would go here
                    false
                }
            }
            AttestSigAlg::EcdsaP256 => {
                // ECDSA P-256 verification would go here
                false
            }
        }
    }
}

#[derive(Clone, Copy)]
pub enum AttestSigAlg { Ed25519, EcdsaP256 }

#[derive(thiserror::Error, Debug)]
pub enum AttestError {
    #[error("policy rejected RA evidence")]
    Policy,
    #[error("invalid signature")]
    InvalidSig,
    #[error("stale attestation")]
    Stale,
    #[error("internal")]
    Internal,
}

/// Compute the exact bytes that the enclave signs.
/// This must be *identical* in enclave and validator.
pub fn attested_message_bytes<E: Pairing>(env: &Envelope<E>) -> Vec<u8> {
    let mut buf = Vec::new();
    
    // Serialize: eid || x_hat || S || ct1..ct4 || ts || nonce
    buf.extend_from_slice(&env.eid.0.to_le_bytes());
    
    // Serialize x (ct.x) to 32 bytes
    let mut x_bytes = Vec::new();
    env.ct.x.serialize_compressed(&mut x_bytes).unwrap();
    buf.extend_from_slice(&x_bytes);
    
    // Serialize gs (S = g^s) 
    let mut gs_bytes = Vec::new();
    env.ct.gs.serialize_compressed(&mut gs_bytes).unwrap();
    buf.extend_from_slice(&gs_bytes);
    
    // Add ciphertext components
    buf.extend_from_slice(&env.ct.ct1);
    
    let mut ct2_bytes = Vec::new();
    env.ct.ct2.serialize_compressed(&mut ct2_bytes).unwrap();
    buf.extend_from_slice(&ct2_bytes);
    
    let mut ct3_bytes = Vec::new();
    env.ct.ct3.serialize_compressed(&mut ct3_bytes).unwrap();
    buf.extend_from_slice(&ct3_bytes);
    
    let mut ct4_bytes = Vec::new();
    env.ct.ct4.serialize_compressed(&mut ct4_bytes).unwrap();
    buf.extend_from_slice(&ct4_bytes);
    
    if let Some(att) = &env.att {
        buf.extend_from_slice(&att.ts_unix_ms.to_le_bytes());
        buf.extend_from_slice(&att.nonce);
    }
    
    // Hash the concatenated bytes for a fixed-size message
    blake3::hash(&buf).as_bytes().to_vec()
}

/// Accept-or-verify gate used by validators BEFORE partial decryption:
/// 1) If `att.is_some()` and RA+sig verify => *skip* proof checks (fast path).
/// 2) Else, run the full cryptographic check (pure-crypto path, identical to today).
pub fn accept_or_verify<E: Pairing>(
    env: &Envelope<E>,
    pol: &AcceptancePolicy,
    av: &dyn AttestationVerifier,
    htau: &E::G2,
    pk: &E::G2,
) -> Result<(), VerifyGateError> {
    if let Some(att) = &env.att {
        let apub = av.verify_and_extract_pubkey(&att.quote, pol)?;
        // Verify signature over the agreed message
        let msg = attested_message_bytes(env);
        if apub.verify(&msg, &att.sig) && is_fresh(att.ts_unix_ms, pol) {
            return Ok(()); // fast-path admitted: proofs need not be re-verified
        }
        // Fall through to cryptographic verification on failure.
    }
    // Pure-crypto fallback:
    crate::verification::verify_ciphertext_relation(&env.ct, htau, pk)
        .map_err(VerifyGateError::Crypto)
}

fn is_fresh(_ts_ms: u64, _pol: &AcceptancePolicy) -> bool {
    // TODO(impl): wall-clock check; use user time source
    true
}

#[derive(thiserror::Error, Debug)]
pub enum VerifyGateError {
    #[error(transparent)]
    Crypto(#[from] crate::verification::VerifyError),
    #[error(transparent)]
    Attest(#[from] AttestError),
}

/// Development-only attestation verifier that accepts a hardcoded key
#[cfg(feature = "dev-attest")]
pub struct DevAttestationVerifier {
    pub dev_pubkey: Vec<u8>, // Ed25519 public key bytes
}

#[cfg(feature = "dev-attest")]
impl AttestationVerifier for DevAttestationVerifier {
    fn verify_and_extract_pubkey(&self, _quote: &[u8], pol: &AcceptancePolicy) -> Result<AttestPubKey, AttestError> {
        if !pol.dev_mode {
            return Err(AttestError::Policy);
        }
        
        Ok(AttestPubKey {
            alg: AttestSigAlg::Ed25519,
            key_bytes: self.dev_pubkey.clone(),
        })
    }
}
