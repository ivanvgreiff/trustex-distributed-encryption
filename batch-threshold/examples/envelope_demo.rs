//! End-to-end example demonstrating the envelope-based workflow with TEE attestations.
//! This shows the hybrid approach: some ciphertexts with attestations (fast-path),
//! some without (fallback to crypto verification).

#[cfg(all(feature = "tee-ingress", feature = "dev-attest"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use batch_threshold::*;
    use ark_bls12_381::Bls12_381;
    use ark_std::UniformRand;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use rand::thread_rng;
    use std::collections::BTreeMap;
    use ed25519_dalek::{SigningKey, Signer};
    
    type E = Bls12_381;
    type Fr = <E as ark_ec::pairing::Pairing>::ScalarField;
    type G1 = <E as ark_ec::pairing::Pairing>::G1;
    
    println!("🚀 HbTPKE-TEE Envelope Demo");
    println!("Demonstrating hybrid attestation + crypto verification\n");
    
    let mut rng = thread_rng();
    
    // === SETUP PHASE ===
    println!("📋 Setup Phase:");
    let batch_size = 8;
    let n = 6;
    let t = 2; // Need t+1 = 3 parties to decrypt
    
    println!("  • Batch size: {}", batch_size);
    println!("  • Total parties: {}", n);
    println!("  • Threshold: {} (need {} parties to decrypt)", t, t + 1);
    
    let mut dealer = dealer::Dealer::<E>::new(batch_size, n, t);
    let (crs, secret_shares) = dealer.setup(&mut rng);
    let pk = dealer.get_pk();
    
    // Create secret keys for parties
    let mut secret_keys = Vec::new();
    for share in secret_shares {
        secret_keys.push(decryption::SecretKey::new(share));
    }
    
    println!("  ✅ Dealer setup complete\n");
    
    // === ENCRYPTION PHASE ===
    println!("🔐 Encryption Phase:");
    let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
    let hid = G1::rand(&mut rng);
    
    let messages: Vec<[u8; 32]> = (0..batch_size)
        .map(|i| {
            let mut msg = [0u8; 32];
            msg[0] = i as u8;
            msg[1] = 0xAB; // Marker
            msg
        })
        .collect();
    
    let mut ciphertexts = Vec::new();
    for (i, &msg) in messages.iter().enumerate() {
        let x = tx_domain.element(i);
        let ct = encryption::encrypt::<E>(msg, x, hid, crs.htau, pk, &mut rng);
        ciphertexts.push(ct);
        println!("  • Encrypted message {}: {:02x}{:02x}...", i, msg[0], msg[1]);
    }
    
    println!("  ✅ All messages encrypted\n");
    
    // === ATTESTATION SETUP ===
    println!("🛡️ Attestation Setup:");
    
    // Create dev signing key (in production, this would be RA-bound)
    let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
    let verifying_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
    
    let policy = attestation::AcceptancePolicy {
        max_skew_ms: 60000, // 1 minute
        allowlisted_measurements: vec![],
        dev_mode: true,
    };
    
    let verifier = attestation::DevAttestationVerifier {
        dev_pubkey: verifying_key_bytes,
    };
    
    println!("  • Dev attestation key generated");
    println!("  • Acceptance policy configured (dev mode)");
    
    // === CREATE ENVELOPES (MIXED BATCH) ===
    println!("📦 Creating Envelopes (Mixed Batch):");
    
    let mut envelopes = Vec::new();
    for (i, ct) in ciphertexts.iter().enumerate() {
        if i % 2 == 0 {
            // Even indices: Create with attestation (fast-path)
            let ts_unix_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64;
            let nonce: [u8; 16] = rand::random();
            
            let envelope = envelope::Envelope {
                eid: envelope::EpochId(1),
                ct: ct.clone(),
                att: Some(envelope::IngressAttestation {
                    sig: Vec::new(), // Will be filled after signing
                    quote: Vec::new(), // Empty in dev mode
                    ts_unix_ms,
                    nonce,
                }),
            };
            
            // Sign the attested message
            let message_bytes = attestation::attested_message_bytes(&envelope);
            let signature = signing_key.sign(&message_bytes);
            
            let envelope_with_sig = envelope::Envelope {
                eid: envelope::EpochId(1),
                ct: ct.clone(),
                att: Some(envelope::IngressAttestation {
                    sig: signature.to_bytes().to_vec(),
                    quote: Vec::new(),
                    ts_unix_ms,
                    nonce,
                }),
            };
            
            envelopes.push(envelope_with_sig);
            println!("  • Message {} → Envelope WITH attestation (fast-path)", i);
        } else {
            // Odd indices: No attestation (crypto fallback)
            let envelope = envelope::Envelope {
                eid: envelope::EpochId(1),
                ct: ct.clone(),
                att: None,
            };
            envelopes.push(envelope);
            println!("  • Message {} → Envelope WITHOUT attestation (crypto fallback)", i);
        }
    }
    
    println!("  ✅ Mixed batch created: {} attested, {} crypto fallback\n", 
             batch_size / 2, batch_size - batch_size / 2);
    
    // === VERIFICATION PHASE ===
    println!("✅ Verification Phase:");
    
    let start = std::time::Instant::now();
    for (i, env) in envelopes.iter().enumerate() {
        match attestation::accept_or_verify(env, &policy, &verifier, &crs.htau, &pk) {
            Ok(_) => {
                let path = if env.att.is_some() { "attestation" } else { "crypto" };
                println!("  • Envelope {} verified via {} path", i, path);
            },
            Err(e) => {
                println!("  ❌ Envelope {} failed verification: {}", i, e);
                return Err(e.into());
            }
        }
    }
    let verification_time = start.elapsed();
    
    println!("  ✅ All envelopes verified in {:?}\n", verification_time);
    
    // === PARTIAL DECRYPTION PHASE ===
    println!("🔓 Partial Decryption Phase:");
    println!("  Note: Using original partial_decrypt for correctness demo");
    println!("  (envelope-based method would use the same verification gate)");
    
    // Use first t+1 parties for decryption
    let mut partial_decryptions = BTreeMap::new();
    
    let start = std::time::Instant::now();
    for party_id in 0..=t {
        // Extract ciphertexts from envelopes for original method
        let ciphertexts_for_decrypt: Vec<_> = envelopes.iter().map(|env| env.ct.clone()).collect();
        let pd = secret_keys[party_id].partial_decrypt(
            &ciphertexts_for_decrypt, hid, pk, &crs
        );
        partial_decryptions.insert(party_id, pd);
        println!("  • Party {} computed partial decryption", party_id);
    }
    let partial_decrypt_time = start.elapsed();
    
    println!("  ✅ Partial decryptions computed in {:?}\n", partial_decrypt_time);
    
    // === AGGREGATION & FULL DECRYPTION ===
    println!("🔄 Aggregation & Full Decryption:");
    
    let start = std::time::Instant::now();
    let sigma = decryption::aggregate_partial_decryptions(&partial_decryptions);
    
    // Extract ciphertexts from envelopes for decrypt_all
    let ciphertexts_for_decrypt: Vec<_> = envelopes.iter().map(|env| env.ct.clone()).collect();
    let recovered_messages = decryption::decrypt_all(sigma, &ciphertexts_for_decrypt, hid, &crs);
    let full_decrypt_time = start.elapsed();
    
    println!("  ✅ Full decryption completed in {:?}\n", full_decrypt_time);
    
    // === VERIFICATION OF RESULTS ===
    println!("🎯 Results Verification:");
    
    let mut all_correct = true;
    for (i, (original, recovered)) in messages.iter().zip(recovered_messages.iter()).enumerate() {
        if original == recovered {
            println!("  ✅ Message {}: {:02x}{:02x}... → {:02x}{:02x}... ✓", 
                    i, original[0], original[1], recovered[0], recovered[1]);
        } else {
            println!("  ❌ Message {}: {:02x}{:02x}... → {:02x}{:02x}... ✗", 
                    i, original[0], original[1], recovered[0], recovered[1]);
            all_correct = false;
        }
    }
    
    // === PERFORMANCE SUMMARY ===
    println!("\n📊 Performance Summary:");
    println!("  • Verification time: {:?}", verification_time);
    println!("  • Partial decryption: {:?}", partial_decrypt_time);
    println!("  • Full decryption: {:?}", full_decrypt_time);
    println!("  • Total time: {:?}", verification_time + partial_decrypt_time + full_decrypt_time);
    
    println!("\n🎉 Demo completed successfully!");
    println!("The hybrid approach allows validators to skip expensive proof verification");
    println!("for attested ciphertexts while maintaining security through graceful fallback.");
    
    if all_correct {
        Ok(())
    } else {
        Err("Some messages were not correctly decrypted".into())
    }
}

#[cfg(not(all(feature = "tee-ingress", feature = "dev-attest")))]
fn main() {
    eprintln!("This example requires --features tee-ingress,dev-attest");
    eprintln!("Run with: cargo run --example envelope_demo --features tee-ingress,dev-attest");
}
