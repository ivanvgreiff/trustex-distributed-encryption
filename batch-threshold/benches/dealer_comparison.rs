use batch_threshold::dealer::{CRS, Dealer};
use batch_threshold::attested_dealer::{
    DevAttestedDealerClient, AttestedDealerClient, accept_attested_dealing, PartyId
};
use batch_threshold::dealer_ra::{DealerAcceptancePolicy, DevAttestationVerifier};
use batch_threshold::dealer_consistency::{verify_same_tau, verify_pk_from_share_commitments};

use ark_bls12_381::Bls12_381 as E;
use ark_ec::{CurveGroup, PrimeGroup};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::SeedableRng;
use std::time::Instant;

fn benchmark_original_dealer(c: &mut Criterion) {
    let mut group = c.benchmark_group("original_dealer_setup");
    
    // Align with HbTPKE-TEE evaluation plan: B ∈ {128, 512}, n ∈ {16, 64, 128}
    for &(batch_size, n, t) in &[(128, 16, 7), (128, 64, 31), (128, 128, 63), (512, 16, 7), (512, 64, 31), (512, 128, 63)] {
        group.throughput(Throughput::Elements(n as u64));
        
        group.bench_with_input(
            BenchmarkId::new("setup_and_verify", format!("B{}_n{}_t{}", batch_size, n, t)),
            &(batch_size, n, t),
            |b, &(batch_size, n, t)| {
                b.iter(|| {
                    let mut rng = rand::rngs::StdRng::from_entropy();
                    let mut dealer = Dealer::<E>::new(batch_size, n, t);
                    let pk = dealer.get_pk();
                    let (crs, shares) = dealer.setup(&mut rng);
                    
                    // Simulate the consistency checks that would be done by validators
                    // In the original system, these would be expensive pairing operations
                    let same_tau_valid = verify_same_tau::<E>(&crs);
                    
                    // Build per-share commitments for verification
                    let per_share_pks: Vec<_> = shares.iter().enumerate().map(|(i, share)| {
                        let h_share = (<E as ark_ec::pairing::Pairing>::G2::generator() * share).into_affine();
                        (PartyId(i as u32 + 1), h_share)
                    }).collect();
                    
                    let share_commitments_valid = verify_pk_from_share_commitments::<E>(
                        n, &pk.into_affine(), &per_share_pks
                    );
                    
                    black_box((crs, shares, same_tau_valid, share_commitments_valid));
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_attested_dealer(c: &mut Criterion) {
    let mut group = c.benchmark_group("attested_dealer_setup");
    
    // Align with HbTPKE-TEE evaluation plan: B ∈ {128, 512}, n ∈ {16, 64, 128}
    for &(batch_size, n, t) in &[(128, 16, 7), (128, 64, 31), (128, 128, 63), (512, 16, 7), (512, 64, 31), (512, 128, 63)] {
        group.throughput(Throughput::Elements(n as u64));
        
        group.bench_with_input(
            BenchmarkId::new("generate_and_accept", format!("B{}_n{}_t{}", batch_size, n, t)),
            &(batch_size, n, t),
            |b, &(batch_size, n, t)| {
                // Setup reused across iterations
                let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
                let measurement = *b"DEV_MEASUREMENT_TAG_32_BYTES_LNG";
                let client = DevAttestedDealerClient::<E>::new(signing, measurement);
                let party_ids: Vec<_> = (1..=n as u32).map(PartyId).collect();
                let policy = DealerAcceptancePolicy {
                    max_skew_ms: 60_000,
                    allowlisted_measurements: vec![measurement],
                    dev_mode: true,
                };
                let verifier = DevAttestationVerifier;
                
                b.iter(|| {
                    let mut rng = rand::rngs::StdRng::from_entropy();
                    
                    // Generate attested dealing
                    let dealing = client.generate(&mut rng, batch_size, n, t, &party_ids);
                    
                    // Accept with all verification checks (attestation + consistency)
                    let verified_setup = accept_attested_dealing::<E, _>(&dealing, &policy, &verifier)
                        .expect("attested dealing should be acceptable");
                    
                    black_box(verified_setup);
                });
            },
        );
    }
    
    group.finish();
}

fn benchmark_verification_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_only");
    
    // Pre-generate test data for fair comparison
    let batch_size = 128;
    let n = 32;
    let t = 15;
    let party_ids: Vec<_> = (1..=n as u32).map(PartyId).collect();
    
    // Generate original dealer output
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut original_dealer = Dealer::<E>::new(batch_size, n, t);
    let original_pk = original_dealer.get_pk();
    let (original_crs, original_shares) = original_dealer.setup(&mut rng);
    
    // Generate attested dealer output
    let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let measurement = *b"DEV_MEASUREMENT_TAG_32_BYTES_LNG";
    let attested_client = DevAttestedDealerClient::<E>::new(signing, measurement);
    let attested_dealing = attested_client.generate(&mut rng, batch_size, n, t, &party_ids);
    let policy = DealerAcceptancePolicy {
        max_skew_ms: 60_000,
        allowlisted_measurements: vec![measurement],
        dev_mode: true,
    };
    let verifier = DevAttestationVerifier;
    
    group.bench_function("original_consistency_checks", |b| {
        b.iter(|| {
            // Same-tau verification (expensive pairing operations)
            let same_tau_valid = verify_same_tau::<E>(&original_crs);
            
            // Share commitment verification
            let per_share_pks: Vec<_> = original_shares.iter().enumerate().map(|(i, share)| {
                let h_share = (<E as ark_ec::pairing::Pairing>::G2::generator() * share).into_affine();
                (PartyId(i as u32 + 1), h_share)
            }).collect();
            
            let share_commitments_valid = verify_pk_from_share_commitments::<E>(
                n, &original_pk.into_affine(), &per_share_pks
            );
            
            black_box((same_tau_valid, share_commitments_valid));
        });
    });
    
    group.bench_function("attested_verification", |b| {
        b.iter(|| {
            // This includes Ed25519 signature verification + same consistency checks
            let verified_setup = accept_attested_dealing::<E, _>(&attested_dealing, &policy, &verifier)
                .expect("attested dealing should be acceptable");
            
            black_box(verified_setup);
        });
    });
    
    group.finish();
}

fn benchmark_single_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_operations");
    
    // Setup test data
    let batch_size = 64;
    let n = 16;
    let t = 7;
    
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut dealer = Dealer::<E>::new(batch_size, n, t);
    let (crs, _) = dealer.setup(&mut rng);
    
    // Test Ed25519 signature verification
    let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let test_message = b"test message for signature verification";
    use ed25519_dalek::Signer;
    let signature = signing.sign(test_message);
    let verifying_key = ed25519_dalek::VerifyingKey::from(&signing);
    
    group.bench_function("ed25519_signature_verify", |b| {
        b.iter(|| {
            let result = verifying_key.verify_strict(black_box(test_message), black_box(&signature));
            black_box(result);
        });
    });
    
    group.bench_function("crs_same_tau_check", |b| {
        b.iter(|| {
            let result = verify_same_tau::<E>(black_box(&crs));
            black_box(result);
        });
    });
    
    group.finish();
}

criterion_group!(
    benches,
    benchmark_original_dealer,
    benchmark_attested_dealer,
    benchmark_verification_only,
    benchmark_single_operations
);
criterion_main!(benches);
