//! AttestedSetup (dev-mode) — one-time DKG/PoT coordinator + audit scaffolding.
//! No real TEE. Produces public transcripts + optional dev attestation.

use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup, AffineRepr};
use ark_ff::{PrimeField, Zero, One};
use ark_serialize::CanonicalSerialize;
use ark_std::vec::Vec;
use serde::{Deserialize, Serialize};

use time::OffsetDateTime;

use crate::dealer::{CRS, Dealer};          // existing

use thiserror::Error;

#[cfg(feature = "dev-attested-setup")]
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};

/// Input describing the one-time setup job.
#[derive(Clone, Debug)]
pub struct DealerInput<F: PrimeField> {
    pub batch_size: usize,
    pub n: usize,
    pub t: usize,
    /// Public Shamir abscissae (e.g., [1,2,...,n] in F). Must match share order.
    pub share_domain: Vec<F>,
    /// Optional pointer to known PoT (e.g., "eth-kzg-ceremony").
    pub pot_id: Option<String>,
}

/// Public commitments from the one-time DKG.
#[derive(Clone, Debug)]
pub struct DealerCommitments<E: Pairing> {
    pub pk: E::G2Affine,                        // h^sk
    pub share_commitments: Vec<E::G2Affine>,    // { h^[sk]_j }
}

/// Canonical metadata bound into the transcript digest.
#[derive(Clone, Debug)]
pub struct AttestedSetupMeta<F: PrimeField> {
    pub version: u32,
    pub batch_size: usize,
    pub n: usize,
    pub t: usize,
    pub share_domain: Vec<F>,
    pub pot_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetupAttestation {
    pub sig: Vec<u8>,             // dev: Ed25519(signature over digest||ts)
    pub quote: Vec<u8>,           // dev: empty
    pub ts_unix_ms: u64,          // freshness
    pub measurement: [u8; 32],    // dev placeholder (e.g., blake3("attested-setup-dev@v1"))
}

/// Everything a node needs to verify one-time setup.
#[derive(Clone, Debug)]
pub struct AttestedDealing<E: Pairing> {
    pub crs: CRS<E>,
    /// Only for dev/testing. In production, AttestedSetup never outputs long-term secrets.
    pub shares: Vec<E::ScalarField>,
    pub commitments: DealerCommitments<E>,
    pub transcript_digest: [u8; 32],
    pub attestation: Option<SetupAttestation>,
    pub meta: AttestedSetupMeta<E::ScalarField>,
}

/// Acceptance policy for dev-mode.
#[derive(Clone, Debug)]
pub struct DealerPolicy {
    pub dev_mode: bool,
    pub max_skew_ms: u64,
    pub allowlisted_measurements: Vec<[u8; 32]>,
    #[cfg(feature = "dev-attested-setup")]
    pub dev_verifying_key: Option<VerifyingKey>,
}

#[derive(Error, Debug)]
pub enum AttestedSetupError {
    #[error("invalid inputs: {0}")]
    InvalidInput(&'static str),
    #[error("CRS too short")]
    CrsTooShort,
    #[error("CRS same-τ check failed at index {index}")]
    CrsInconsistent { index: usize },
    #[error("share commitments length mismatch")]
    CommitLen,
    #[error("pk from commitments mismatch")]
    PkMismatch,
    #[error("attestation required by policy")]
    AttestationMissing,
    #[error("attestation signature invalid")]
    BadSignature,
    #[error("attestation timestamp skew too large")]
    BadTimestamp,
    #[error("measurement not allowlisted")]
    MeasurementRejected,
}

/// --- Public API -------------------------------------------------------------

/// Crypto-only (no dev signature). Uses existing Dealer as stand-in for one-time DKG.
pub fn run_attested_setup_crypto_only<E: Pairing, R: rand::RngCore>(
    mut rng: R,
    inp: DealerInput<E::ScalarField>,
) -> Result<AttestedDealing<E>, AttestedSetupError> {
    validate_input::<E>(&inp)?;

    // Use your existing Dealer as a DKG stand-in for tests.
    let mut dealer = Dealer::<E>::new_with_rng(inp.batch_size, inp.n, inp.t, &mut rng);
    let (crs, shares) = dealer.setup(&mut rng);

    let commitments = compute_commitments::<E>(&shares);
    let pk = compute_pk_from_commitments::<E>(&inp.share_domain, &commitments.share_commitments)?;
    let commitments = DealerCommitments { pk, share_commitments: commitments.share_commitments };

    let meta = AttestedSetupMeta {
        version: 1,
        batch_size: inp.batch_size,
        n: inp.n,
        t: inp.t,
        share_domain: inp.share_domain.clone(),
        pot_id: inp.pot_id.clone(),
    };

    let transcript_digest = digest_transcript::<E>(&crs, &commitments, &meta);
    Ok(AttestedDealing { crs, shares, commitments, transcript_digest, attestation: None, meta })
}

#[cfg(feature = "dev-attested-setup")]
pub fn run_attested_setup_dev<E: Pairing, R: rand::RngCore>(
    mut rng: R,
    inp: DealerInput<E::ScalarField>,
    dev_sk: &SigningKey,
) -> Result<AttestedDealing<E>, AttestedSetupError> {
    let mut deal = run_attested_setup_crypto_only::<E, _>(&mut rng, inp)?;

    // Produce a dev-mode "quote": Ed25519(signature over digest || ts).
    let ts = OffsetDateTime::now_utc().unix_timestamp_nanos() as u128 / 1_000_000;
    let ts_bytes = (ts as u64).to_le_bytes();

    let mut to_sign = Vec::with_capacity(32 + 8);
    to_sign.extend_from_slice(&deal.transcript_digest);
    to_sign.extend_from_slice(&ts_bytes);

    let sig: Signature = dev_sk.try_sign(&to_sign).expect("ed25519 sign");
    let measurement = *blake3::hash(b"attested-setup-dev@v1").as_bytes();

    deal.attestation = Some(SetupAttestation {
        sig: sig.to_bytes().to_vec(),
        quote: Vec::new(),
        ts_unix_ms: ts as u64,
        measurement,
    });
    Ok(deal)
}

/// Node-side verification: public checks + (optional) dev signature policy.
pub fn verify_attested_dealing<E: Pairing>(
    deal: &AttestedDealing<E>,
    pol: &DealerPolicy,
) -> Result<(), AttestedSetupError> {
    // 1) CRS sanity: same-τ check
    verify_crs_same_tau::<E>(&deal.crs)?;

    // 2) pk from share commitments via Lagrange-at-0 (public check)
    let pk2 = compute_pk_from_commitments::<E>(
        &deal.meta.share_domain,
        &deal.commitments.share_commitments,
    )?;
    if pk2 != deal.commitments.pk {
        return Err(AttestedSetupError::PkMismatch);
    }

    // 3) Attestation policy
    if let Some(att) = &deal.attestation {
        // Check measurement allowlist if provided
        if !pol.allowlisted_measurements.is_empty()
            && !pol.allowlisted_measurements.iter().any(|m| m == &att.measurement)
        {
            return Err(AttestedSetupError::MeasurementRejected);
        }

        // Dev-mode specific checks
        if pol.dev_mode {
            if pol.max_skew_ms > 0 {
                let now_ms = (OffsetDateTime::now_utc().unix_timestamp_nanos() as u128 / 1_000_000) as u64;
                if now_ms.saturating_sub(att.ts_unix_ms) > pol.max_skew_ms {
                    return Err(AttestedSetupError::BadTimestamp);
                }
            }

            #[cfg(feature = "dev-attested-setup")]
            {
                let vk = pol.dev_verifying_key.as_ref().ok_or(AttestedSetupError::AttestationMissing)?;
                let mut msg = Vec::with_capacity(32 + 8);
                msg.extend_from_slice(&deal.transcript_digest);
                msg.extend_from_slice(&att.ts_unix_ms.to_le_bytes());
                let sig_bytes: [u8; 64] = att.sig.as_slice().try_into().map_err(|_| AttestedSetupError::BadSignature)?;
                let sig = Signature::from_bytes(&sig_bytes);
                vk.verify_strict(&msg, &sig).map_err(|_| AttestedSetupError::BadSignature)?;
            }
        }
    } else if pol.dev_mode {
        return Err(AttestedSetupError::AttestationMissing);
    }
    Ok(())
}

/// --- Helpers ---------------------------------------------------------------

fn validate_input<E: Pairing>(inp: &DealerInput<E::ScalarField>) -> Result<(), AttestedSetupError> {
    if inp.n == 0 || inp.share_domain.len() != inp.n {
        return Err(AttestedSetupError::InvalidInput("share_domain length must equal n"));
    }
    if inp.t >= inp.n {
        return Err(AttestedSetupError::InvalidInput("t must be < n"));
    }
    Ok(())
}

/// Compute {h^[sk]_j} and pk = h^sk, return both.
fn compute_commitments<E: Pairing>(
    shares: &[E::ScalarField],
) -> DealerCommitments<E> {
    let g2 = E::G2::generator();
    let mut share_commitments = Vec::with_capacity(shares.len());
    let mut acc = E::G2::zero();
    for s in shares {
        let c = (g2 * s).into_affine();
        share_commitments.push(c);
        acc += c;
    }
    // The sum is not (in general) equal to h^sk; pk is reconstructed below from Lagrange-at-0.
    DealerCommitments { pk: acc.into_affine(), share_commitments }
}

/// Compute pk from commitments using Lagrange-at-0 over the public abscissae.
fn compute_pk_from_commitments<E: Pairing>(
    domain: &[E::ScalarField],
    comms: &[E::G2Affine],
) -> Result<E::G2Affine, AttestedSetupError> {
    if domain.len() != comms.len() {
        return Err(AttestedSetupError::CommitLen);
    }
    let lambdas = lagrange_at_zero::<E::ScalarField>(domain);
    let mut acc = E::G2::zero();
    for (c, lam) in comms.iter().zip(lambdas.iter()) {
        acc += c.mul_bigint(lam.into_bigint());
    }
    Ok(acc.into_affine())
}

/// Standard Lagrange weights at x=0.
fn lagrange_at_zero<F: PrimeField>(xs: &[F]) -> Vec<F> {
    xs.iter().enumerate().map(|(j, &xj)| {
        let mut num = F::one(); // ∏_{i≠j} (0 - x_i) = ∏ (-x_i)
        let mut den = F::one(); // ∏_{i≠j} (x_j - x_i)
        for (i, &xi) in xs.iter().enumerate() {
            if i == j { continue; }
            num *= -xi;
            den *= xj - xi;
        }
        num * den.inverse().unwrap()
    }).collect()
}

/// CRS same-τ: e(g^{τ^i}, h) == e(g^{τ^{i-1}}, h^τ) for i=1..B-1.
fn verify_crs_same_tau<E: Pairing>(crs: &CRS<E>) -> Result<(), AttestedSetupError> {
    let h = E::G2::generator().into_affine();
    let htau = crs.htau.into_affine();
    let p = &crs.powers_of_g;
    if p.len() < 2 { return Err(AttestedSetupError::CrsTooShort); }
    for i in 1..p.len() {
        let lhs = E::pairing(p[i], h);
        let rhs = E::pairing(p[i - 1], htau);
        if lhs != rhs {
            return Err(AttestedSetupError::CrsInconsistent { index: i });
        }
    }
    Ok(())
}

/// Canonical transcript digest = H( meta || CRS || commitments ).
fn digest_transcript<E: Pairing>(
    crs: &CRS<E>,
    com: &DealerCommitments<E>,
    meta: &AttestedSetupMeta<E::ScalarField>,
) -> [u8; 32] {
    let mut ser = Vec::new();

    // Meta
    ser.extend_from_slice(&meta.version.to_le_bytes());
    ser.extend_from_slice(&(meta.batch_size as u64).to_le_bytes());
    ser.extend_from_slice(&(meta.n as u64).to_le_bytes());
    ser.extend_from_slice(&(meta.t as u64).to_le_bytes());
    for x in &meta.share_domain {
        let mut buf = Vec::new();
        x.serialize_compressed(&mut buf).unwrap();
        ser.extend_from_slice(&buf);
    }
    if let Some(id) = &meta.pot_id {
        ser.extend_from_slice(id.as_bytes());
    }

    // CRS
    for g1 in &crs.powers_of_g {
        let mut buf = Vec::new();
        g1.serialize_compressed(&mut buf).unwrap();
        ser.extend_from_slice(&buf);
    }
    {
        let mut buf = Vec::new();
        crs.htau.serialize_compressed(&mut buf).unwrap();
        ser.extend_from_slice(&buf);
    }

    // Commitments
    {
        let mut buf = Vec::new();
        com.pk.serialize_compressed(&mut buf).unwrap();
        ser.extend_from_slice(&buf);
    }
    for c in &com.share_commitments {
        let mut buf = Vec::new();
        c.serialize_compressed(&mut buf).unwrap();
        ser.extend_from_slice(&buf);
    }

    *blake3::hash(&ser).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Bls12_381 as E;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[cfg(feature = "dev-attested-setup")]
    use ed25519_dalek::SigningKey;

    fn create_test_input() -> DealerInput<<E as Pairing>::ScalarField> {
        let n = 5;
        let t = 2;
        let batch_size = 8;
        let share_domain = (1..=n)
            .map(|i| <E as Pairing>::ScalarField::from(i as u64))
            .collect();

        DealerInput {
            batch_size,
            n,
            t,
            share_domain,
            pot_id: Some("test-ceremony".to_string()),
        }
    }

    #[test]
    fn test_crypto_only_setup() {
        let mut rng = StdRng::seed_from_u64(42);
        let inp = create_test_input();

        let dealing = run_attested_setup_crypto_only::<E, _>(&mut rng, inp).unwrap();
        
        assert_eq!(dealing.shares.len(), 5);
        assert_eq!(dealing.commitments.share_commitments.len(), 5);
        assert!(dealing.attestation.is_none());
        assert_eq!(dealing.meta.version, 1);
        assert_eq!(dealing.meta.n, 5);
        assert_eq!(dealing.meta.t, 2);
    }

    #[cfg(feature = "dev-attested-setup")]
    #[test]
    fn test_dev_setup_with_attestation() {
        let mut rng = StdRng::seed_from_u64(42);
        let inp = create_test_input();
        let dev_sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());

        let dealing = run_attested_setup_dev::<E, _>(&mut rng, inp, &dev_sk).unwrap();
        
        assert!(dealing.attestation.is_some());
        let att = dealing.attestation.as_ref().unwrap();
        assert!(!att.sig.is_empty());
        assert_eq!(att.measurement, *blake3::hash(b"attested-setup-dev@v1").as_bytes());
    }

    #[test]
    fn test_crs_same_tau_verification() {
        let mut rng = StdRng::seed_from_u64(42);
        let inp = create_test_input();

        let dealing = run_attested_setup_crypto_only::<E, _>(&mut rng, inp).unwrap();
        
        // Should pass with valid CRS
        assert!(verify_crs_same_tau::<E>(&dealing.crs).is_ok());
    }

    #[test]
    fn test_pk_from_commitments_verification() {
        let mut rng = StdRng::seed_from_u64(42);
        let inp = create_test_input();

        let dealing = run_attested_setup_crypto_only::<E, _>(&mut rng, inp).unwrap();
        
        // Verify pk matches what we compute from commitments
        let pk2 = compute_pk_from_commitments::<E>(
            &dealing.meta.share_domain,
            &dealing.commitments.share_commitments,
        ).unwrap();
        assert_eq!(pk2, dealing.commitments.pk);
    }

    #[test]
    fn test_pk_mismatch_detection() {
        let mut rng = StdRng::seed_from_u64(42);
        let inp = create_test_input();

        let mut dealing = run_attested_setup_crypto_only::<E, _>(&mut rng, inp).unwrap();
        
        // Corrupt the pk
        dealing.commitments.pk = <E as Pairing>::G2::generator().into_affine();
        
        let policy = DealerPolicy {
            dev_mode: false,
            max_skew_ms: 0,
            allowlisted_measurements: Vec::new(),
            #[cfg(feature = "dev-attested-setup")]
            dev_verifying_key: None,
        };

        assert!(matches!(
            verify_attested_dealing::<E>(&dealing, &policy),
            Err(AttestedSetupError::PkMismatch)
        ));
    }

    #[cfg(feature = "dev-attested-setup")]
    #[test]
    fn test_signature_verification() {
        let mut rng = StdRng::seed_from_u64(42);
        let inp = create_test_input();
        let dev_sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let dev_vk = dev_sk.verifying_key();

        let dealing = run_attested_setup_dev::<E, _>(&mut rng, inp, &dev_sk).unwrap();
        
        let policy = DealerPolicy {
            dev_mode: true,
            max_skew_ms: 60_000,
            allowlisted_measurements: vec![*blake3::hash(b"attested-setup-dev@v1").as_bytes()],
            dev_verifying_key: Some(dev_vk),
        };

        assert!(verify_attested_dealing::<E>(&dealing, &policy).is_ok());
    }

    #[cfg(feature = "dev-attested-setup")]
    #[test]
    fn test_bad_signature_rejection() {
        let mut rng = StdRng::seed_from_u64(42);
        let inp = create_test_input();
        let dev_sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let wrong_sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let wrong_vk = wrong_sk.verifying_key();

        let dealing = run_attested_setup_dev::<E, _>(&mut rng, inp, &dev_sk).unwrap();
        
        let policy = DealerPolicy {
            dev_mode: true,
            max_skew_ms: 60_000,
            allowlisted_measurements: vec![*blake3::hash(b"attested-setup-dev@v1").as_bytes()],
            dev_verifying_key: Some(wrong_vk),
        };

        assert!(matches!(
            verify_attested_dealing::<E>(&dealing, &policy),
            Err(AttestedSetupError::BadSignature)
        ));
    }

    #[test]
    fn test_measurement_allowlist() {
        let mut rng = StdRng::seed_from_u64(42);
        let inp = create_test_input();

        let mut dealing = run_attested_setup_crypto_only::<E, _>(&mut rng, inp).unwrap();
        
        // Add fake attestation with wrong measurement
        dealing.attestation = Some(SetupAttestation {
            sig: Vec::new(),
            quote: Vec::new(),
            ts_unix_ms: 1000,
            measurement: [0u8; 32], // Wrong measurement
        });

        let policy = DealerPolicy {
            dev_mode: false, // Don't require signature verification, just check measurement
            max_skew_ms: 60_000,
            allowlisted_measurements: vec![*blake3::hash(b"attested-setup-dev@v1").as_bytes()],
            #[cfg(feature = "dev-attested-setup")]
            dev_verifying_key: None,
        };

        assert!(matches!(
            verify_attested_dealing::<E>(&dealing, &policy),
            Err(AttestedSetupError::MeasurementRejected)
        ));
    }

    #[test]
    fn test_input_validation() {
        let mut rng = StdRng::seed_from_u64(42);
        
        // Test invalid share_domain length
        let bad_inp = DealerInput {
            batch_size: 8,
            n: 5,
            t: 2,
            share_domain: vec![<E as Pairing>::ScalarField::from(1u64)], // Wrong length
            pot_id: None,
        };

        assert!(matches!(
            run_attested_setup_crypto_only::<E, _>(&mut rng, bad_inp),
            Err(AttestedSetupError::InvalidInput(_))
        ));

        // Test t >= n
        let bad_inp2 = DealerInput {
            batch_size: 8,
            n: 5,
            t: 5, // t should be < n
            share_domain: (1..=5).map(|i| <E as Pairing>::ScalarField::from(i as u64)).collect(),
            pot_id: None,
        };

        assert!(matches!(
            run_attested_setup_crypto_only::<E, _>(&mut rng, bad_inp2),
            Err(AttestedSetupError::InvalidInput(_))
        ));
    }

    #[test]
    fn test_transcript_digest_stability() {
        let inp = create_test_input();

        // Use the same seed twice to get the same random values
        let dealing1 = run_attested_setup_crypto_only::<E, _>(StdRng::seed_from_u64(42), inp.clone()).unwrap();
        let dealing2 = run_attested_setup_crypto_only::<E, _>(StdRng::seed_from_u64(42), inp).unwrap();
        
        // Same seed should produce same transcript digest
        assert_eq!(dealing1.transcript_digest, dealing2.transcript_digest);
        
        // Different seeds should produce different digests
        let dealing3 = run_attested_setup_crypto_only::<E, _>(StdRng::seed_from_u64(123), create_test_input()).unwrap();
        assert_ne!(dealing1.transcript_digest, dealing3.transcript_digest);
    }
}
