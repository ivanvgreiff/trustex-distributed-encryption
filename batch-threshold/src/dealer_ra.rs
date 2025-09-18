// batch-threshold/src/dealer_ra.rs
#![cfg(feature = "tee-dealer")]

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct DealerAcceptancePolicy {
    pub max_skew_ms: u64,
    pub allowlisted_measurements: Vec<[u8; 32]>,
    pub dev_mode: bool,
}

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("dev mode disabled")]
    DevModeDisabled,
    #[error("measurement not allowlisted")]
    MeasurementNotAllowed,
    #[error("timestamp skew too large")]
    TimestampSkew,
    #[error("signature verification failed")]
    BadSignature,
}

pub trait AttestationVerifier {
    /// Validate RA evidence and return the public key used to verify the signature over transcript.
    fn verify_and_extract_pubkey(
        &self,
        quote: &[u8],
        policy: &DealerAcceptancePolicy,
        att: &crate::attested_dealer::DealerAttestation,
    ) -> Result<AttestPubKey, AttestError>;
}

/// Currently only dev Ed25519 verifier. Real RA backends can be added behind other features.
pub struct DevAttestationVerifier;

#[derive(Debug, Clone)]
pub enum AttestPubKey {
    #[cfg(feature = "dev-attest")]
    Ed25519(ed25519_dalek::VerifyingKey),
}

impl AttestPubKey {
    pub fn verify(
        &self,
        msg_digest32: &[u8; 32],
        att: &crate::attested_dealer::DealerAttestation
    ) -> Result<(), AttestError> {
        match self {
            #[cfg(feature = "dev-attest")]
            AttestPubKey::Ed25519(vk) => {
                let sig = ed25519_dalek::Signature::from_bytes(&att.sig_ed25519);
                vk.verify_strict(msg_digest32, &sig).map_err(|_| AttestError::BadSignature)
            }
        }
    }
}

impl AttestationVerifier for DevAttestationVerifier {
    fn verify_and_extract_pubkey(
        &self,
        _quote: &[u8],
        policy: &DealerAcceptancePolicy,
        att: &crate::attested_dealer::DealerAttestation,
    ) -> Result<AttestPubKey, AttestError> {
        if !policy.dev_mode {
            return Err(AttestError::DevModeDisabled);
        }
        let now_ms = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()) as u64;
        if att.ts_unix_ms > now_ms + policy.max_skew_ms || now_ms > att.ts_unix_ms + policy.max_skew_ms {
            return Err(AttestError::TimestampSkew);
        }
        if !policy.allowlisted_measurements.iter().any(|m| *m == att.measurement) {
            return Err(AttestError::MeasurementNotAllowed);
        }
        
        #[cfg(feature = "dev-attest")]
        {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&att.pubkey_ed25519).map_err(|_| AttestError::BadSignature)?;
            Ok(AttestPubKey::Ed25519(vk))
        }
        #[cfg(not(feature = "dev-attest"))]
        {
            Err(AttestError::DevModeDisabled)
        }
    }
}
