// batch-threshold/src/attested_dealer.rs
#![cfg(feature = "tee-dealer")]

use crate::dealer::{CRS, Dealer};
use crate::dealer_consistency::{verify_same_tau, verify_pk_from_share_commitments};
use crate::dealer_ra::{DealerAcceptancePolicy, AttestationVerifier};
use crate::dealer_transcript::{attested_dealer_message_bytes, digest32};

use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup};
use rand::{RngCore, CryptoRng};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PartyId(pub u32);

#[derive(Debug, Clone)]
pub struct DealerCommitments<E: Pairing> {
    pub pk: E::G2Affine,                                  // h^sk
    pub per_share_pks: Vec<(PartyId, E::G2Affine)>,        // h^{[sk]_i}
}

#[derive(Debug, Clone)]
pub struct ShareForParty<E: Pairing> {
    pub id: PartyId,
    pub sk_share: E::ScalarField,
}

#[derive(Debug, Clone)]
pub struct DealerAttestation {
    pub ts_unix_ms: u64,
    pub nonce: [u8; 16],
    pub measurement: [u8; 32],  // "MRENCLAVE"-like dev tag
    pub pubkey_ed25519: [u8; 32],
    pub sig_ed25519: [u8; 64],  // Signature over attested message bytes (see dealer_transcript)
    pub quote: Vec<u8>,         // empty in dev mode
}

/// The complete attested output of the one-time setup (dev-mode attestation).
#[derive(Debug, Clone)]
pub struct AttestedDealing<E: Pairing> {
    pub batch_size: usize,
    pub n: usize,
    pub t: usize,

    pub crs: CRS<E>,
    pub commitments: DealerCommitments<E>,
    pub shares: Vec<ShareForParty<E>>,   // NOTE: In production these are delivered privately
    pub transcript_digest: [u8; 32],
    pub attestation: DealerAttestation,
}

/// What nodes get back after acceptance: exactly what your code expects today.
#[derive(Debug, Clone)]
pub struct VerifiedSetup<E: Pairing> {
    pub crs: CRS<E>,
    pub shares: Vec<ShareForParty<E>>,
    pub commitments: DealerCommitments<E>,
}

#[derive(Debug, Error)]
pub enum AttestedDealerError {
    #[error("attestation verification failed: {0}")]
    Attestation(String),
    #[error("CRS same-τ checks failed")]
    CRSConsistency,
    #[error("share commitments do not interpolate to pk")]
    ShareCommitments,
    #[error("mismatch in structural expectations (lens, ids)")]
    Structure,
}

/// Trait that abstracts the AttestedDealer "client".
pub trait AttestedDealerClient<E: Pairing> {
    /// Produce an attested dealing (dev mode: signed transcript, no real TEE).
    fn generate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        batch_size: usize,
        n: usize,
        t: usize,
        party_ids: &[PartyId],
    ) -> AttestedDealing<E>;
}

/// Development-only attested dealer that wraps your existing `Dealer` and signs a transcript.
#[cfg(feature = "dev-attest")]
pub struct DevAttestedDealerClient<E: Pairing> {
    /// dev-mode attestation signing keypair (ed25519); the verifier will accept it under policy.dev_mode
    pub signing_key: ed25519_dalek::SigningKey,
    /// fixed dev "measurement" value used in policy allowlist
    pub measurement: [u8; 32],
    _marker: std::marker::PhantomData<E>,
}

#[cfg(feature = "dev-attest")]
impl<E: Pairing> DevAttestedDealerClient<E> {
    pub fn new(signing_key: ed25519_dalek::SigningKey, measurement: [u8; 32]) -> Self {
        Self { signing_key, measurement, _marker: Default::default() }
    }
}

#[cfg(feature = "dev-attest")]
impl<E: Pairing> AttestedDealerClient<E> for DevAttestedDealerClient<E> {
    fn generate<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        batch_size: usize,
        n: usize,
        t: usize,
        party_ids: &[PartyId],
    ) -> AttestedDealing<E> {
        // 1) Use existing Dealer to generate CRS + shares
        let mut dealer = Dealer::<E>::new(batch_size, n, t);
        let pk = dealer.get_pk();
        let (crs, shares_scalar) = dealer.setup(rng);

        assert_eq!(shares_scalar.len(), n);

        // 2) Build commitments: pk = h^sk ; per-share commitments = h^{[sk]_i}
        let mut per_share_pks = Vec::with_capacity(n);
        for (i, share) in shares_scalar.iter().enumerate() {
            let h_share = (E::G2::generator() * share).into_affine();
            per_share_pks.push((party_ids[i], h_share));
        }
        let commitments = DealerCommitments {
            pk: pk.into_affine(),
            per_share_pks,
        };

        // 3) Wrap secret shares with PartyId for downstream private delivery / tests
        let shares = shares_scalar
            .into_iter()
            .enumerate()
            .map(|(i, sk_share)| ShareForParty { id: party_ids[i], sk_share })
            .collect::<Vec<_>>();

        // 4) Transcript digest & attestation
        let msg = attested_dealer_message_bytes::<E>(batch_size, n, t, &crs, &commitments, &shares);
        let digest = digest32(&msg);

        use rand::Rng;
        let mut nonce = [0u8; 16];
        rng.fill(&mut nonce);
        let ts_unix_ms = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis()) as u64;

        // ed25519 signature in dev mode
        use ed25519_dalek::Signer;
        let sig = self.signing_key.sign(&digest);
        let attestation = DealerAttestation {
            ts_unix_ms,
            nonce,
            measurement: self.measurement,
            pubkey_ed25519: ed25519_dalek::VerifyingKey::from(&self.signing_key).to_bytes(),
            sig_ed25519: sig.to_bytes(),
            quote: Vec::new(),
        };

        AttestedDealing {
            batch_size, n, t,
            crs,
            commitments,
            shares,
            transcript_digest: digest,
            attestation,
        }
    }
}

/// Node-side acceptance function: RA (dev), CRS same-τ, and share-commitment checks.
/// Returns a VerifiedSetup that can be fed into the rest of your code unchanged.
pub fn accept_attested_dealing<E: Pairing, V: AttestationVerifier>(
    dealing: &AttestedDealing<E>,
    policy: &DealerAcceptancePolicy,
    verifier: &V,
) -> Result<VerifiedSetup<E>, AttestedDealerError> {
    // 1) Verify attestation (dev path: signature over transcript digest + allowlisted measurement).
    let msg = attested_dealer_message_bytes::<E>(
        dealing.batch_size, dealing.n, dealing.t, &dealing.crs, &dealing.commitments, &dealing.shares
    );
    let digest = digest32(&msg);

    let pubkey = verifier.verify_and_extract_pubkey(
        &dealing.attestation.quote,
        policy,
        &dealing.attestation
    ).map_err(|e| AttestedDealerError::Attestation(e.to_string()))?;

    // signature check
    pubkey.verify(&digest, &dealing.attestation)
        .map_err(|e| AttestedDealerError::Attestation(e.to_string()))?;

    // 2) CRS consistency: ensure g-powers share the same τ as h^τ (cheap pairing checks).
    if !verify_same_tau::<E>(&dealing.crs) {
        return Err(AttestedDealerError::CRSConsistency);
    }

    // 3) Share-commitment check: Lagrange interpolate pk from {h^{[sk]_i}} equals committed pk.
    if !verify_pk_from_share_commitments::<E>(
        dealing.n,
        &dealing.commitments.pk,
        &dealing.commitments.per_share_pks
    ) {
        return Err(AttestedDealerError::ShareCommitments);
    }

    Ok(VerifiedSetup {
        crs: dealing.crs.clone(),
        shares: dealing.shares.clone(),
        commitments: dealing.commitments.clone(),
    })
}
