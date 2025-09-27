use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ark_bls12_381::Bls12_381 as E;
use batch_threshold::dealer::Dealer;
use batch_threshold::attested_setup::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[cfg(feature = "dev-attested-setup")]
use ed25519_dalek::SigningKey;

/// Benchmark baseline DKG setup (traditional approach)
fn baseline_dkg_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("Setup Efficiency Comparison");
    
    // Test different committee sizes as mentioned in HbTPKE-TEE spec
    for &n in &[16usize, 64, 128] {
        let t = n / 2; // Simple threshold
        let batch_size = 512; // Realistic batch size from spec
        
        group.bench_function(&format!("baseline_dkg_n{}", n), |b| {
            b.iter(|| {
                let mut rng = StdRng::seed_from_u64(42);
                let mut dealer = Dealer::<E>::new_with_rng(batch_size, n, t, &mut rng);
                let (crs, shares) = dealer.setup(&mut rng);
                black_box((crs, shares));
            });
        });
    }
    
    group.finish();
}

/// Benchmark AttestedSetup crypto-only mode
fn attested_setup_crypto_only(c: &mut Criterion) {
    let mut group = c.benchmark_group("AttestedSetup Crypto-Only");
    
    for &n in &[16usize, 64, 128] {
        let t = n / 2;
        let batch_size = 512;
        let share_domain: Vec<_> = (1..=n)
            .map(|i| <E as ark_ec::pairing::Pairing>::ScalarField::from(i as u64))
            .collect();
        
        let input = DealerInput {
            batch_size,
            n,
            t,
            share_domain,
            pot_id: Some("eth-kzg-ceremony".to_string()),
        };
        
        group.bench_function(&format!("attested_crypto_only_n{}", n), |b| {
            b.iter(|| {
                let rng = StdRng::seed_from_u64(42);
                let dealing = run_attested_setup_crypto_only::<E, _>(rng, input.clone()).unwrap();
                black_box(dealing);
            });
        });
    }
    
    group.finish();
}

/// Benchmark AttestedSetup dev mode with signatures
#[cfg(feature = "dev-attested-setup")]
fn attested_setup_dev_mode(c: &mut Criterion) {
    let mut group = c.benchmark_group("AttestedSetup Dev Mode");
    
    for &n in &[16usize, 64, 128] {
        let t = n / 2;
        let batch_size = 512;
        let share_domain: Vec<_> = (1..=n)
            .map(|i| <E as ark_ec::pairing::Pairing>::ScalarField::from(i as u64))
            .collect();
        
        let input = DealerInput {
            batch_size,
            n,
            t,
            share_domain,
            pot_id: Some("eth-kzg-ceremony".to_string()),
        };
        
        group.bench_function(&format!("attested_dev_mode_n{}", n), |b| {
            b.iter(|| {
                let rng = StdRng::seed_from_u64(42);
                let dev_sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
                let dealing = run_attested_setup_dev::<E, _>(rng, input.clone(), &dev_sk).unwrap();
                black_box(dealing);
            });
        });
    }
    
    group.finish();
}

/// Benchmark verification overhead
fn verification_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verification Overhead");
    
    let n = 64;
    let t = 32;
    let batch_size = 512;
    let share_domain: Vec<_> = (1..=n)
        .map(|i| <E as ark_ec::pairing::Pairing>::ScalarField::from(i as u64))
        .collect();
    
    let input = DealerInput {
        batch_size,
        n,
        t,
        share_domain,
        pot_id: Some("eth-kzg-ceremony".to_string()),
    };
    
    // Prepare test data
    let rng = StdRng::seed_from_u64(42);
    let dealing = run_attested_setup_crypto_only::<E, _>(rng, input.clone()).unwrap();
    
    let policy_crypto_only = DealerPolicy {
        dev_mode: false,
        max_skew_ms: 0,
        allowlisted_measurements: Vec::new(),
        #[cfg(feature = "dev-attested-setup")]
        dev_verifying_key: None,
    };
    
    #[cfg(feature = "dev-attested-setup")]
    let policy_dev_mode = {
        let rng = StdRng::seed_from_u64(42);
        let dev_sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let dev_dealing = run_attested_setup_dev::<E, _>(rng, input.clone(), &dev_sk).unwrap();
        let policy = DealerPolicy {
            dev_mode: true,
            max_skew_ms: 60_000,
            allowlisted_measurements: vec![*blake3::hash(b"attested-setup-dev@v1").as_bytes()],
            dev_verifying_key: Some(dev_sk.verifying_key()),
        };
        (dev_dealing, policy)
    };
    
    group.bench_function("verify_crypto_only", |b| {
        b.iter(|| {
            let result = verify_attested_dealing::<E>(&dealing, &policy_crypto_only);
            let _ = black_box(result);
        });
    });
    
    #[cfg(feature = "dev-attested-setup")]
    group.bench_function("verify_dev_mode", |b| {
        let (ref dev_dealing, ref policy) = policy_dev_mode;
        b.iter(|| {
            let result = verify_attested_dealing::<E>(dev_dealing, policy);
            let _ = black_box(result);
        });
    });
    
    group.finish();
}

/// Benchmark transcript digest computation
fn transcript_digest_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Transcript Digest");
    
    for &n in &[16usize, 64, 128] {
        let t = n / 2;
        let batch_size = 512;
        let share_domain: Vec<_> = (1..=n)
            .map(|i| <E as ark_ec::pairing::Pairing>::ScalarField::from(i as u64))
            .collect();
        
        let input = DealerInput {
            batch_size,
            n,
            t,
            share_domain,
            pot_id: Some("eth-kzg-ceremony".to_string()),
        };
        
        // Pre-compute the dealing to isolate digest computation
        let rng = StdRng::seed_from_u64(42);
        let dealing = run_attested_setup_crypto_only::<E, _>(rng, input).unwrap();
        
        group.bench_function(&format!("digest_computation_n{}", n), |b| {
            b.iter(|| {
                // The digest is computed during setup, but we can benchmark just the hash
                let mut hasher = blake3::Hasher::new();
                
                // Simulate the serialization overhead (this is what digest_transcript does)
                hasher.update(&dealing.meta.version.to_le_bytes());
                hasher.update(&(dealing.meta.batch_size as u64).to_le_bytes());
                hasher.update(&(dealing.meta.n as u64).to_le_bytes());
                hasher.update(&(dealing.meta.t as u64).to_le_bytes());
                
                // Add some representative data (simplified from the actual implementation)
                for g1 in &dealing.crs.powers_of_g {
                    let mut buf = Vec::new();
                    ark_serialize::CanonicalSerialize::serialize_compressed(g1, &mut buf).unwrap();
                    hasher.update(&buf);
                }
                
                let digest = hasher.finalize();
                black_box(digest);
            });
        });
    }
    
    group.finish();
}

#[cfg(feature = "dev-attested-setup")]
criterion_group!(
    benches,
    baseline_dkg_setup,
    attested_setup_crypto_only,
    attested_setup_dev_mode,
    verification_overhead,
    transcript_digest_benchmark
);

#[cfg(not(feature = "dev-attested-setup"))]
criterion_group!(
    benches,
    baseline_dkg_setup,
    attested_setup_crypto_only,
    verification_overhead,
    transcript_digest_benchmark
);

criterion_main!(benches);
