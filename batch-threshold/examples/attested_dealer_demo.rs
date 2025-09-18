// cargo run -p batch-threshold --example attested_dealer_demo --features tee-dealer,dev-attest
#![cfg(all(feature = "tee-dealer", feature = "dev-attest"))]

use ark_bls12_381::Bls12_381 as E;
use batch_threshold::attested_dealer::{
    DevAttestedDealerClient, AttestedDealerClient, accept_attested_dealing
};
use batch_threshold::dealer_ra::{DealerAcceptancePolicy, DevAttestationVerifier};

fn main() {
    // Parameters
    let batch_size = 32usize;
    let n = 8usize;
    let t = 3usize;
    let party_ids: Vec<_> = (1..=n as u32).map(batch_threshold::attested_dealer::PartyId).collect();

    // Dev attestation identity
    use rand::SeedableRng;
    let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let measurement = *b"DEV_MEASUREMENT_TAG_32_BYTES_LNG"; // 32-bytes tag

    let client = DevAttestedDealerClient::<E>::new(signing, measurement);
    let mut rng = rand::rngs::StdRng::from_entropy();

    // Produce an AttestedDealing (no TEE; signed transcript)
    let dealing = client.generate(&mut rng, batch_size, n, t, &party_ids);

    // Node policy & verifier (dev mode on)
    let policy = DealerAcceptancePolicy {
        max_skew_ms: 60_000,
        allowlisted_measurements: vec![measurement],
        dev_mode: true,
    };
    let verifier = DevAttestationVerifier;

    // Gate: attestation + CRS same-τ + share-commitment checks
    let verified = accept_attested_dealing::<E, _>(&dealing, &policy, &verifier)
        .expect("attested dealing should be acceptable");

    println!("Verified setup accepted: B={}, n={}, t={}", batch_size, n, t);
    println!("CRS powers: {}", verified.crs.powers_of_g.len());
    println!("Shares delivered: {}", verified.shares.len());
    println!("pk: {:?}", verified.commitments.pk);
}
