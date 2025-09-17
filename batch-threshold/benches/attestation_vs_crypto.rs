use batch_threshold::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

#[cfg(all(feature = "tee-ingress", feature = "dev-attest"))]
use batch_threshold::{
    attestation::*,
    envelope::*,
};

use ark_bls12_381::Bls12_381;
use ark_std::UniformRand;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rand::thread_rng;

type E = Bls12_381;
type Fr = <Bls12_381 as ark_ec::pairing::Pairing>::ScalarField;
type G1 = <Bls12_381 as ark_ec::pairing::Pairing>::G1;

#[cfg(all(feature = "tee-ingress", feature = "dev-attest"))]
fn setup_test_data(batch_size: usize) -> (
    dealer::CRS<E>,
    <E as ark_ec::pairing::Pairing>::G2,
    Vec<encryption::Ciphertext<E>>,
    Vec<Envelope<E>>,
    AcceptancePolicy,
    DevAttestationVerifier,
    G1,
) {
    use ed25519_dalek::{SigningKey, Signer};
    
    let mut rng = thread_rng();
    
    // Setup dealer and keys
    let n = 16;
    let mut dealer = dealer::Dealer::<E>::new(batch_size, n, n / 2 - 1);
    let (crs, _) = dealer.setup(&mut rng);
    let pk = dealer.get_pk();
    
    // Create batch of ciphertexts
    let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
    let mut ciphertexts = Vec::new();
    let hid = G1::rand(&mut rng);
    
    for i in 0..batch_size {
        let msg = [(i as u8); 32];
        let x = tx_domain.element(i);
        let ct = encryption::encrypt::<E>(msg, x, hid, crs.htau, pk, &mut rng);
        ciphertexts.push(ct);
    }
    
    // Create dev signing key for attestations
    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let verifying_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
    
    // Create envelopes with attestations
    let mut envelopes = Vec::new();
    for (i, ct) in ciphertexts.iter().enumerate() {
        let ts_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let nonce: [u8; 16] = rand::random();
        
        let envelope = Envelope {
            eid: EpochId(1),
            ct: ct.clone(),
            att: Some(IngressAttestation {
                sig: Vec::new(), // Will be filled after message construction
                quote: Vec::new(),
                ts_unix_ms,
                nonce,
            }),
        };
        
        // Sign the attested message
        let message_bytes = attested_message_bytes(&envelope);
        let signature = signing_key.sign(&message_bytes);
        
        let envelope_with_sig = Envelope {
            eid: EpochId(1),
            ct: ct.clone(),
            att: Some(IngressAttestation {
                sig: signature.to_bytes().to_vec(),
                quote: Vec::new(),
                ts_unix_ms,
                nonce,
            }),
        };
        
        envelopes.push(envelope_with_sig);
    }
    
    let policy = AcceptancePolicy {
        max_skew_ms: 60000,
        allowlisted_measurements: vec![],
        dev_mode: true,
    };
    
    let verifier = DevAttestationVerifier {
        dev_pubkey: verifying_key_bytes,
    };
    
    (crs, pk, ciphertexts, envelopes, policy, verifier, hid)
}

#[cfg(all(feature = "tee-ingress", feature = "dev-attest"))]
fn bench_crypto_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_comparison");
    
    for batch_size in [4, 16, 64, 256].iter() {
        let (crs, pk, ciphertexts, _envelopes, _policy, _verifier, _hid) = setup_test_data(*batch_size);
        
        // Benchmark: Pure cryptographic verification (baseline)
        group.bench_with_input(
            BenchmarkId::new("crypto_verify_batch", batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    for ct in &ciphertexts {
                        black_box(verification::verify_ciphertext_relation(
                            ct, &crs.htau, &pk
                        ).unwrap());
                    }
                });
            },
        );
    }
    
    group.finish();
}

#[cfg(all(feature = "tee-ingress", feature = "dev-attest"))]
fn bench_attestation_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_comparison");
    
    for batch_size in [4, 16, 64, 256].iter() {
        let (crs, pk, _ciphertexts, envelopes, policy, verifier, _hid) = setup_test_data(*batch_size);
        
        // Benchmark: Attestation verification (fast-path)
        group.bench_with_input(
            BenchmarkId::new("attestation_verify_batch", batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    for env in &envelopes {
                        black_box(accept_or_verify(
                            env, &policy, &verifier, &crs.htau, &pk
                        ).unwrap());
                    }
                });
            },
        );
    }
    
    group.finish();
}

#[cfg(all(feature = "tee-ingress", feature = "dev-attest"))]
fn bench_mixed_batch_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("verification_comparison");
    
    for batch_size in [16, 64, 256].iter() {
        let (crs, pk, ciphertexts, envelopes, policy, verifier, _hid) = setup_test_data(*batch_size);
        
        // Create mixed batch: 50% with attestations, 50% without
        let mut mixed_envelopes = Vec::new();
        for (i, ct) in ciphertexts.iter().enumerate() {
            if i % 2 == 0 {
                // Even indices: use attestation from prepared envelopes
                mixed_envelopes.push(envelopes[i].clone());
            } else {
                // Odd indices: no attestation (fallback to crypto)
                mixed_envelopes.push(Envelope {
                    eid: EpochId(1),
                    ct: ct.clone(),
                    att: None,
                });
            }
        }
        
        // Benchmark: Mixed batch verification
        group.bench_with_input(
            BenchmarkId::new("mixed_verify_batch", batch_size),
            batch_size,
            |b, _| {
                b.iter(|| {
                    for env in &mixed_envelopes {
                        black_box(accept_or_verify(
                            env, &policy, &verifier, &crs.htau, &pk
                        ).unwrap());
                    }
                });
            },
        );
    }
    
    group.finish();
}

#[cfg(all(feature = "tee-ingress", feature = "dev-attest"))]
fn bench_single_operation_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("single_operation_comparison");
    
    let (crs, pk, ciphertexts, envelopes, policy, verifier, _hid) = setup_test_data(1);
    let ct = &ciphertexts[0];
    let env = &envelopes[0];
    
    // Single crypto verification
    group.bench_function("single_crypto_verify", |b| {
        b.iter(|| {
            black_box(verification::verify_ciphertext_relation(
                ct, &crs.htau, &pk
            ).unwrap());
        });
    });
    
    // Single attestation verification
    group.bench_function("single_attestation_verify", |b| {
        b.iter(|| {
            black_box(accept_or_verify(
                env, &policy, &verifier, &crs.htau, &pk
            ).unwrap());
        });
    });
    
    group.finish();
}

#[cfg(all(feature = "tee-ingress", feature = "dev-attest"))]
criterion_group!(
    benches,
    bench_crypto_verification,
    bench_attestation_verification,
    bench_mixed_batch_verification,
    bench_single_operation_comparison
);

#[cfg(not(all(feature = "tee-ingress", feature = "dev-attest")))]
fn bench_features_disabled(_c: &mut Criterion) {
    eprintln!("Attestation benchmarks require --features tee-ingress,dev-attest");
}

#[cfg(not(all(feature = "tee-ingress", feature = "dev-attest")))]
criterion_group!(benches, bench_features_disabled);

criterion_main!(benches);
