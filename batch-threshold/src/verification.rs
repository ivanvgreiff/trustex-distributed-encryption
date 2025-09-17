//! Shared verification helpers used by validators and ingress enclave.
//! NOTE: logic mirrors the proof checks used in `Ciphertext::verify`.

use ark_ec::{pairing::Pairing, PrimeGroup};
use ark_ff::Field;
use merlin::Transcript;

use crate::encryption::Ciphertext;
use crate::utils::add_to_transcript;

/// Error type for verification failures
#[derive(thiserror::Error, Debug)]
pub enum VerifyError {
    #[error("Invalid proof: challenge mismatch")]
    ChallengeMismatch,
    #[error("Invalid proof: verification failed")]
    ProofInvalid,
}

/// Verifies the *cryptographic relation* without any RA logic.
/// This contains exactly what `Ciphertext::verify` checks today,
/// using the same Merlin transcript bindings.
pub fn verify_ciphertext_relation<E: Pairing>(
    ct: &Ciphertext<E>,
    htau: &E::G2,
    pk: &E::G2,
) -> Result<(), VerifyError> {
    let g = E::G1::generator();
    let h = E::G2::generator();

    // k2.ct2^c = h^{(tau-x)*z_alpha}, k3.ct3^c = h^{z_alpha} * pk^{z_beta}, k4.ct4^c = h^{z_beta}, and k_s.gs^c = g^{z_s}
    let minus_c = -ct.pi.c;
    let recovered_k2 = (*htau - (h * ct.x)) * ct.pi.z_alpha + (ct.ct2 * minus_c);
    let recovered_k3 = h * ct.pi.z_alpha + *pk * ct.pi.z_beta + (ct.ct3 * minus_c);
    let recovered_k4 = h * ct.pi.z_beta + (ct.ct4 * minus_c);
    let recovered_k_s = g * ct.pi.z_s + (ct.gs * minus_c);

    let mut ts: Transcript = Transcript::new(&[0u8]);
    add_to_transcript(&mut ts, b"ct1", ct.ct1);
    add_to_transcript(&mut ts, b"ct2", ct.ct2);
    add_to_transcript(&mut ts, b"ct3", ct.ct3);
    add_to_transcript(&mut ts, b"ct4", ct.ct4);
    add_to_transcript(&mut ts, b"gs", ct.gs);
    add_to_transcript(&mut ts, b"x", ct.x);

    add_to_transcript(&mut ts, b"k2", recovered_k2);
    add_to_transcript(&mut ts, b"k3", recovered_k3);
    add_to_transcript(&mut ts, b"k4", recovered_k4);
    add_to_transcript(&mut ts, b"k_s", recovered_k_s);

    // Fiat-Shamir to get challenge
    let mut c_bytes = [0u8; 31];
    ts.challenge_bytes(&[8u8], &mut c_bytes);
    let c = E::ScalarField::from_random_bytes(&c_bytes)
        .ok_or(VerifyError::ProofInvalid)?;

    // Check that the recomputed challenge matches
    if ct.pi.c != c {
        return Err(VerifyError::ChallengeMismatch);
    }

    Ok(())
}
