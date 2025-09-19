use ark_bls12_381::Bls12_381 as E;
use batch_threshold::attested_setup::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[cfg(feature = "dev-attested-setup")]
use ed25519_dalek::SigningKey;

fn main() {
    let mut rng = StdRng::seed_from_u64(7);

    let n = 16usize;
    let t = 7usize;
    let batch_size = 32usize;

    // Standard Shamir domain [1..=n] in the scalar field.
    let share_domain = (1..=n).map(|i| <E as ark_ec::pairing::Pairing>::ScalarField::from(i as u64)).collect();

    let inp = DealerInput {
        batch_size,
        n,
        t,
        share_domain,
        pot_id: Some("eth-kzg-ceremony".to_string()),
    };

    #[cfg(feature = "dev-attested-setup")]
    let dev_sk = SigningKey::from_bytes(&rand::random::<[u8; 32]>());

    #[cfg(feature = "dev-attested-setup")]
    let dealing = run_attested_setup_dev::<E, _>(&mut rng, inp, &dev_sk).unwrap();

    #[cfg(not(feature = "dev-attested-setup"))]
    let dealing = run_attested_setup_crypto_only::<E, _>(&mut rng, inp).unwrap();

    // Node policy: require dev signature if compiled with dev, allow our placeholder measurement.
    let policy = DealerPolicy {
        dev_mode: cfg!(feature = "dev-attested-setup"),
        max_skew_ms: 60_000,
        allowlisted_measurements: vec![*blake3::hash(b"attested-setup-dev@v1").as_bytes()],
        #[cfg(feature = "dev-attested-setup")]
        dev_verifying_key: Some(dev_sk.verifying_key()),
    };

    verify_attested_dealing::<E>(&dealing, &policy).expect("attested dealing verified");
    
    println!("✅ AttestedSetup Demo Complete!");
    println!("📋 Setup Parameters:");
    println!("   - Batch size: {}", dealing.meta.batch_size);
    println!("   - Parties (n): {}", dealing.meta.n);
    println!("   - Threshold (t): {}", dealing.meta.t);
    println!("   - PoT ID: {:?}", dealing.meta.pot_id);
    
    println!("🔐 Cryptographic Artifacts:");
    println!("   - CRS powers: {} elements", dealing.crs.powers_of_g.len());
    println!("   - Share commitments: {} elements", dealing.commitments.share_commitments.len());
    println!("   - Transcript digest: {}", hex::encode(dealing.transcript_digest));
    
    #[cfg(feature = "dev-attested-setup")]
    if let Some(att) = &dealing.attestation {
        println!("🛡️  Dev Attestation:");
        println!("   - Signature length: {} bytes", att.sig.len());
        println!("   - Timestamp: {} ms", att.ts_unix_ms);
        println!("   - Measurement: {}", hex::encode(att.measurement));
    } else {
        println!("🔓 No attestation (crypto-only mode)");
    }
    
    #[cfg(not(feature = "dev-attested-setup"))]
    println!("🔓 No attestation (crypto-only mode)");
    
    println!("✨ All verifications passed!");
}
