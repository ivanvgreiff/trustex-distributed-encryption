// batch-threshold/src/dealer_consistency.rs
#![cfg(feature = "tee-dealer")]

use crate::dealer::CRS;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, PrimeGroup, AffineRepr};
use ark_ff::PrimeField;
use ark_std::Zero;

/// Check that all g1 powers share the same τ as h^τ.
/// We require: for i>=1, e(g^{τ^i}, h) == e(g^{τ^{i-1}}, h^τ)
/// Also: e(g^{τ}, h) == e(g, h^τ).
pub fn verify_same_tau<E: Pairing>(crs: &CRS<E>) -> bool {
    let g_pows = &crs.powers_of_g;
    if g_pows.len() < 2 {
        return false;
    }
    let h = E::G2::generator().into_affine();
    let htau = crs.htau;

    // e(g^{τ}, h) == e(g, h^{τ})
    let left0 = E::pairing(g_pows[1], h);
    let right0 = E::pairing(g_pows[0], htau);
    if left0 != right0 {
        return false;
    }

    // For i=2.., e(g^{τ^i}, h) == e(g^{τ^{i-1}}, h^τ)
    for i in 2..g_pows.len() {
        let left = E::pairing(g_pows[i], h);
        let right = E::pairing(g_pows[i - 1], htau);
        if left != right {
            return false;
        }
    }
    true
}

/// Compute Lagrange coefficients at 0 for the points x_i = i (1..=n).
fn lagrange_coeffs_at_zero<F: PrimeField>(n: usize) -> Vec<F> {
    // λ_i(0) = ∏_{j != i} (-x_j) / (x_i - x_j), with x_i = i
    let mut coeffs = Vec::with_capacity(n);
    for i in 1..=n {
        let xi = F::from(i as u64);
        let mut num = F::one();
        let mut den = F::one();
        for j in 1..=n {
            if i == j { continue; }
            let xj = F::from(j as u64);
            num *= -xj;
            den *= xi - xj;
        }
        coeffs.push(num * den.inverse().unwrap());
    }
    coeffs
}

/// Verify that ∏ (h^{[sk]_i})^{λ_i} = h^{sk}, i.e., Lagrange interpolation in the exponent matches pk.
pub fn verify_pk_from_share_commitments<E: Pairing>(
    n: usize,
    pk: &E::G2Affine,
    per_share_pks: &Vec<(super::attested_dealer::PartyId, E::G2Affine)>,
) -> bool {
    if per_share_pks.len() != n { return false; }

    let coeffs = lagrange_coeffs_at_zero::<E::ScalarField>(n);

    let mut acc = E::G2::zero();
    for ((_, h_share), lam) in per_share_pks.iter().zip(coeffs.iter()) {
        acc += h_share.into_group() * lam;
    }
    acc.into_affine() == *pk
}
