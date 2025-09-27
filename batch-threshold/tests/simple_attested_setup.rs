//! Simplified AttestedSetup for testing purposes
//! 
//! This module provides a basic implementation of attested setup functionality
//! for evaluation purposes when the full attested-setup feature is not available.

use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::Pairing;
use ark_ec::{PrimeGroup, CurveGroup, AffineRepr};
use ark_ff::{PrimeField, Zero};
use ark_serialize::CanonicalSerialize;
use std::vec::Vec;
use thiserror::Error;

use batch_threshold::dealer::{CRS, Dealer};

#[derive(Debug, Clone)]
pub struct DealerInput<F: PrimeField> {
    pub batch_size: usize,
    pub n: usize,
    pub t: usize,
    pub share_domain: Vec<F>,
    pub pot_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DealerCommitments<E: Pairing> {
    pub pk: E::G2Affine,
    pub share_commitments: Vec<E::G2Affine>,
}

#[derive(Debug, Clone)]
pub struct AttestedSetupMeta<F: PrimeField> {
    pub version: u32,
    pub batch_size: usize,
    pub n: usize,
    pub t: usize,
    pub share_domain: Vec<F>,
    pub pot_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AttestedDealing<E: Pairing> {
    pub crs: CRS<E>,
    pub shares: Vec<E::ScalarField>,
    pub commitments: DealerCommitments<E>,
    pub transcript_digest: [u8; 32],
    pub meta: AttestedSetupMeta<E::ScalarField>,
}

#[derive(Error, Debug)]
pub enum AttestedSetupError {
    #[error("invalid inputs: {0}")]
    InvalidInput(&'static str),
    #[error("share commitments length mismatch")]
    CommitLen,
    #[error("pk from commitments mismatch")]
    PkMismatch,
}

/// Simple attested setup implementation for testing
pub fn run_attested_setup_crypto_only<E: Pairing, R: rand::RngCore>(
    mut rng: R,
    inp: DealerInput<E::ScalarField>,
) -> Result<AttestedDealing<E>, AttestedSetupError> {
    validate_input::<E>(&inp)?;
    
    // Use existing Dealer as a DKG stand-in
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
    Ok(AttestedDealing { crs, shares, commitments, transcript_digest, meta })
}

fn validate_input<E: Pairing>(inp: &DealerInput<E::ScalarField>) -> Result<(), AttestedSetupError> {
    if inp.n == 0 || inp.share_domain.len() != inp.n {
        return Err(AttestedSetupError::InvalidInput("share_domain length must equal n"));
    }
    if inp.t >= inp.n {
        return Err(AttestedSetupError::InvalidInput("t must be < n"));
    }
    Ok(())
}

fn compute_commitments<E: Pairing>(shares: &[E::ScalarField]) -> DealerCommitments<E> {
    let g2 = E::G2::generator();
    let mut share_commitments = Vec::with_capacity(shares.len());
    let mut acc = E::G2::zero();
    for s in shares {
        let c = (g2 * s).into_affine();
        share_commitments.push(c);
        acc += c;
    }
    DealerCommitments { pk: acc.into_affine(), share_commitments }
}

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

fn lagrange_at_zero<F: PrimeField>(xs: &[F]) -> Vec<F> {
    use ark_ff::One;
    xs.iter().enumerate().map(|(j, &xj)| {
        let mut num = F::one();
        let mut den = F::one();
        for (i, &xi) in xs.iter().enumerate() {
            if i == j { continue; }
            num *= -xi;
            den *= xj - xi;
        }
        num * den.inverse().unwrap()
    }).collect()
}

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
