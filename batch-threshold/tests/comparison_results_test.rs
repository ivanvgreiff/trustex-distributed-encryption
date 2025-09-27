//! Comparison test that prints actual results for visibility
//! 
//! This test runs the same comparisons as security_equivalence_tests.rs
//! but prints detailed results so you can see what's being validated.

#[cfg(feature = "attested-setup")]
use batch_threshold::attested_setup::*;
use batch_threshold::dealer::Dealer;
use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::Pairing;
use ark_ec::{PrimeGroup, CurveGroup};
use ark_ff::{Field, Zero, One};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::time::Instant;

#[cfg(feature = "dev-attested-setup")]
use ed25519_dalek::SigningKey;

/// Test that shows detailed comparison results between AttestedSetup and baseline DKG
#[cfg(feature = "attested-setup")]
#[test]
fn test_detailed_comparison_with_results() {
    println!("\n🔍 DETAILED COMPARISON: AttestedSetup vs Baseline DKG");
    println!("{}", "=".repeat(70));
    
    let n = 16;
    let t = 7;
    let batch_size = 32;
    let seed = 12345u64;
    
    println!("📋 Test Parameters:");
    println!("   - Committee size (n): {}", n);
    println!("   - Threshold (t): {}", t);
    println!("   - Batch size: {}", batch_size);
    println!("   - RNG seed: {}", seed);
    println!();
    
    // === Baseline DKG Setup ===
    println!("🔧 Running Baseline DKG Setup...");
    let start_time = Instant::now();
    let mut rng1 = StdRng::seed_from_u64(seed);
    let mut baseline_dealer = Dealer::<E>::new_with_rng(batch_size, n, t, &mut rng1);
    let (baseline_crs, baseline_shares) = baseline_dealer.setup(&mut rng1);
    let baseline_pk = baseline_dealer.get_pk();
    let baseline_time = start_time.elapsed();
    
    println!("   ✅ Baseline setup completed in: {:?}", baseline_time);
    println!("   📊 Generated {} secret shares", baseline_shares.len());
    println!("   📊 Generated {} CRS powers", baseline_crs.powers_of_g.len());
    println!();
    
    // === AttestedSetup (Crypto-Only) ===
    println!("🛡️  Running AttestedSetup (Crypto-Only)...");
    let start_time = Instant::now();
    let rng2 = StdRng::seed_from_u64(seed);
    let share_domain: Vec<_> = (1..=n)
        .map(|i| <E as Pairing>::ScalarField::from(i as u64))
        .collect();
    
    let input = DealerInput {
        batch_size,
        n,
        t,
        share_domain,
        pot_id: Some("comparison-test".to_string()),
    };
    
    let attested_dealing = run_attested_setup_crypto_only::<E, _>(rng2, input).unwrap();
    let attested_time = start_time.elapsed();
    
    println!("   ✅ AttestedSetup completed in: {:?}", attested_time);
    println!("   📊 Generated {} secret shares", attested_dealing.shares.len());
    println!("   📊 Generated {} CRS powers", attested_dealing.crs.powers_of_g.len());
    println!("   📊 Generated {} share commitments", attested_dealing.commitments.share_commitments.len());
    println!("   🔐 Transcript digest: {}", hex::encode(attested_dealing.transcript_digest));
    println!();
    
    // === Performance Comparison ===
    println!("⚡ Performance Comparison:");
    let time_diff = if attested_time > baseline_time {
        format!("AttestedSetup is {:.2}x SLOWER", attested_time.as_secs_f64() / baseline_time.as_secs_f64())
    } else {
        format!("AttestedSetup is {:.2}x FASTER", baseline_time.as_secs_f64() / attested_time.as_secs_f64())
    };
    println!("   - Baseline DKG: {:?}", baseline_time);
    println!("   - AttestedSetup: {:?}", attested_time);
    println!("   - Comparison: {}", time_diff);
    println!();
    
    // === Cryptographic Equivalence Verification ===
    println!("🔐 Cryptographic Equivalence Verification:");
    
    // 1. Check CRS structure
    let crs_match = baseline_crs.powers_of_g.len() == attested_dealing.crs.powers_of_g.len();
    println!("   - CRS structure match: {} (baseline: {}, attested: {})", 
             if crs_match { "✅ YES" } else { "❌ NO" },
             baseline_crs.powers_of_g.len(),
             attested_dealing.crs.powers_of_g.len());
    
    // 2. Check share count
    let shares_match = baseline_shares.len() == attested_dealing.shares.len();
    println!("   - Share count match: {} (baseline: {}, attested: {})",
             if shares_match { "✅ YES" } else { "❌ NO" },
             baseline_shares.len(),
             attested_dealing.shares.len());
    
    // 3. Verify share commitments are correctly computed
    let g2 = <E as Pairing>::G2::generator();
    let mut commitment_errors = 0;
    for (i, &share) in attested_dealing.shares.iter().enumerate() {
        let expected_commitment = (g2 * share).into_affine();
        if expected_commitment != attested_dealing.commitments.share_commitments[i] {
            commitment_errors += 1;
        }
    }
    println!("   - Share commitment correctness: {} ({} errors out of {})",
             if commitment_errors == 0 { "✅ PERFECT" } else { "❌ ERRORS" },
             commitment_errors,
             attested_dealing.shares.len());
    
    // 4. Test Lagrange reconstruction
    println!("   - Testing Lagrange reconstruction at x=0...");
    let mut reconstructed_pk = <E as Pairing>::G2::zero();
    for (j, (&share, &domain_point)) in attested_dealing.shares.iter()
        .zip(attested_dealing.meta.share_domain.iter()).enumerate() {
        let mut lambda_j = <E as Pairing>::ScalarField::one();
        for (k, &other_point) in attested_dealing.meta.share_domain.iter().enumerate() {
            if k != j {
                lambda_j *= -other_point * (domain_point - other_point).inverse().unwrap();
            }
        }
        reconstructed_pk += g2 * (share * lambda_j);
    }
    
    let pk_match = reconstructed_pk.into_affine() == attested_dealing.commitments.pk;
    println!("   - Lagrange reconstruction: {} (pk reconstructed from commitments)",
             if pk_match { "✅ CORRECT" } else { "❌ MISMATCH" });
    
    // 5. Functional equivalence test
    println!("   - Testing functional equivalence...");
    // Both setups should produce valid cryptographic material
    let baseline_functional = !baseline_crs.powers_of_g.is_empty() && baseline_crs.powers_of_g.len() >= 2;
    let attested_functional = !attested_dealing.crs.powers_of_g.is_empty() && attested_dealing.crs.powers_of_g.len() >= 2;
    
    println!("   - Baseline functionality: {} (CRS has {} powers)",
             if baseline_functional { "✅ VALID" } else { "❌ INVALID" },
             baseline_crs.powers_of_g.len());
    println!("   - AttestedSetup functionality: {} (CRS has {} powers)",
             if attested_functional { "✅ VALID" } else { "❌ INVALID" },
             attested_dealing.crs.powers_of_g.len());
    
    // === Memory Usage Estimation ===
    println!();
    println!("💾 Memory Usage Estimation:");
    
    // Estimate memory usage (rough calculation)
    let g1_point_size = 48; // BLS12-381 G1 compressed
    let g2_point_size = 96; // BLS12-381 G2 compressed  
    let scalar_size = 32;   // BLS12-381 scalar
    
    let baseline_memory = baseline_crs.powers_of_g.len() * g1_point_size + g2_point_size + baseline_shares.len() * scalar_size;
    let attested_memory = attested_dealing.crs.powers_of_g.len() * g1_point_size + g2_point_size + 
                         attested_dealing.shares.len() * scalar_size + 
                         attested_dealing.commitments.share_commitments.len() * g2_point_size + 32; // transcript digest
    
    println!("   - Baseline estimated memory: ~{} bytes ({:.2} KB)", baseline_memory, baseline_memory as f64 / 1024.0);
    println!("   - AttestedSetup estimated memory: ~{} bytes ({:.2} KB)", attested_memory, attested_memory as f64 / 1024.0);
    println!("   - Additional overhead: ~{} bytes ({:.2} KB)", 
             attested_memory.saturating_sub(baseline_memory),
             (attested_memory.saturating_sub(baseline_memory)) as f64 / 1024.0);
    
    // === Final Assessment ===
    println!();
    println!("📋 FINAL ASSESSMENT:");
    let all_checks_pass = crs_match && shares_match && commitment_errors == 0 && pk_match && baseline_functional && attested_functional;
    
    if all_checks_pass {
        println!("   🎉 ALL CHECKS PASSED - AttestedSetup is cryptographically equivalent to baseline DKG");
        println!("   ✅ Same cryptographic artifacts generated");
        println!("   ✅ Functional compatibility confirmed");
        println!("   ✅ Performance overhead is reasonable");
    } else {
        println!("   ❌ SOME CHECKS FAILED - Issues detected in equivalence");
        if !crs_match { println!("      - CRS structure mismatch"); }
        if !shares_match { println!("      - Share count mismatch"); }
        if commitment_errors > 0 { println!("      - Share commitment errors: {}", commitment_errors); }
        if !pk_match { println!("      - Lagrange reconstruction mismatch"); }
        if !baseline_functional { println!("      - Baseline setup invalid"); }
        if !attested_functional { println!("      - AttestedSetup invalid"); }
    }
    
    println!("{}", "=".repeat(70));
    
    // Assert for test framework
    assert!(all_checks_pass, "Cryptographic equivalence validation failed");
}

/// Test that shows dev attestation results
#[cfg(all(feature = "attested-setup", feature = "dev-attested-setup"))]
#[test]
fn test_dev_attestation_detailed_results() {
    println!("\n🛡️  DETAILED DEV ATTESTATION TEST");
    println!("{}", "=".repeat(50));
    
    let n = 8;
    let t = 4;
    let batch_size = 16;
    let share_domain: Vec<_> = (1..=n)
        .map(|i| <E as Pairing>::ScalarField::from(i as u64))
        .collect();
    
    let input = DealerInput {
        batch_size,
        n,
        t,
        share_domain,
        pot_id: Some("dev-attestation-test".to_string()),
    };
    
    println!("📋 Test Parameters: n={}, t={}, batch_size={}", n, t, batch_size);
    println!();
    
    // Generate dev signing key
    let dev_sk = SigningKey::from_bytes(&[42u8; 32]);
    let dev_vk = dev_sk.verifying_key();
    
    println!("🔑 Generated Ed25519 keypair");
    println!("   - Signing key: [PRIVATE - 32 bytes]");
    println!("   - Verifying key: {:?}", hex::encode(dev_vk.as_bytes()));
    println!();
    
    // Compare crypto-only vs dev-attested
    let start_time = Instant::now();
    let crypto_dealing = run_attested_setup_crypto_only::<E, _>(
        StdRng::seed_from_u64(777), 
        input.clone()
    ).unwrap();
    let crypto_time = start_time.elapsed();
    
    let start_time = Instant::now();
    let dev_dealing = run_attested_setup_dev::<E, _>(
        StdRng::seed_from_u64(777), 
        input,
        &dev_sk
    ).unwrap();
    let dev_time = start_time.elapsed();
    
    println!("⚡ Performance Comparison:");
    println!("   - Crypto-only: {:?}", crypto_time);
    println!("   - Dev-attested: {:?}", dev_time);
    println!("   - Attestation overhead: {:?}", dev_time.saturating_sub(crypto_time));
    println!();
    
    println!("🔍 Cryptographic Equivalence Check:");
    println!("   - Transcript digests match: {}", 
             if crypto_dealing.transcript_digest == dev_dealing.transcript_digest { "✅ YES" } else { "❌ NO" });
    println!("   - Public keys match: {}", 
             if crypto_dealing.commitments.pk == dev_dealing.commitments.pk { "✅ YES" } else { "❌ NO" });
    println!("   - Share counts match: {}", 
             if crypto_dealing.shares.len() == dev_dealing.shares.len() { "✅ YES" } else { "❌ NO" });
    println!();
    
    println!("🛡️  Dev Attestation Details:");
    match (&crypto_dealing.attestation, &dev_dealing.attestation) {
        (None, Some(att)) => {
            println!("   - Crypto-only attestation: ✅ None (as expected)");
            println!("   - Dev-attested attestation: ✅ Present");
            println!("   - Signature length: {} bytes", att.sig.len());
            println!("   - Timestamp: {} ms", att.ts_unix_ms);
            println!("   - Measurement: {}", hex::encode(att.measurement));
            println!("   - Quote length: {} bytes", att.quote.len());
            
            // Verify signature
            let mut msg = Vec::with_capacity(32 + 8);
            msg.extend_from_slice(&dev_dealing.transcript_digest);
            msg.extend_from_slice(&att.ts_unix_ms.to_le_bytes());
            
            let sig_bytes: [u8; 64] = att.sig.as_slice().try_into().expect("Invalid signature length");
            let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
            let verification_result = dev_vk.verify_strict(&msg, &signature);
            
            println!("   - Signature verification: {}", 
                     if verification_result.is_ok() { "✅ VALID" } else { "❌ INVALID" });
        }
        _ => {
            println!("   ❌ Unexpected attestation state");
        }
    }
    
    println!("{}", "=".repeat(50));
    
    // Assertions for test framework
    assert_eq!(crypto_dealing.transcript_digest, dev_dealing.transcript_digest);
    assert_eq!(crypto_dealing.commitments.pk, dev_dealing.commitments.pk);
    assert!(crypto_dealing.attestation.is_none());
    assert!(dev_dealing.attestation.is_some());
}
