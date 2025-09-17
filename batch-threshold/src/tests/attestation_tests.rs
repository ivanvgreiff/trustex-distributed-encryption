#[cfg(all(test, feature = "tee-ingress", feature = "dev-attest"))]
mod tests {
    use crate::attestation::*;
    use crate::envelope::*;
    use crate::dealer::Dealer;
    use crate::encryption::encrypt;
    use ark_bls12_381::Bls12_381;
    use ark_std::UniformRand;
    use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
    use ed25519_dalek::{SigningKey, Signer};
    use rand::thread_rng;

    type E = Bls12_381;
    type Fr = <E as ark_ec::pairing::Pairing>::ScalarField;
    type G1 = <E as ark_ec::pairing::Pairing>::G1;

    #[test]
    fn test_accept_or_verify_with_valid_attestation() {
        let mut rng = thread_rng();
        
        // Setup dealer and keys
        let batch_size = 4;
        let n = 8;
        let mut dealer = Dealer::<E>::new(batch_size, n, n / 2 - 1);
        let (crs, _) = dealer.setup(&mut rng);
        let pk = dealer.get_pk();
        
        // Create test ciphertext
        let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
        let msg = [1u8; 32];
        let x = tx_domain.group_gen;
        let hid = G1::rand(&mut rng);
        let ct = encrypt::<E>(msg, x, hid, crs.htau, pk, &mut rng);
        
        // Create dev signing key and attestation
        let signing_key = SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let verifying_key_bytes = signing_key.verifying_key().to_bytes().to_vec();
        
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
                quote: Vec::new(), // Empty in dev mode
                ts_unix_ms,
                nonce,
            }),
        };
        
        // Sign the attested message
        let message_bytes = crate::attestation::attested_message_bytes(&envelope);
        let signature = signing_key.sign(&message_bytes);
        
        let envelope_with_sig = Envelope {
            eid: EpochId(1),
            ct: ct.clone(),
            att: Some(IngressAttestation {
                sig: signature.to_bytes().to_vec(),
                quote: Vec::new(), // Empty in dev mode
                ts_unix_ms,
                nonce,
            }),
        };
        
        // Create acceptance policy and verifier
        let policy = AcceptancePolicy {
            max_skew_ms: 60000, // 1 minute
            allowlisted_measurements: vec![],
            dev_mode: true,
        };
        
        let verifier = DevAttestationVerifier {
            dev_pubkey: verifying_key_bytes,
        };
        
        // Test: accept_or_verify should succeed with valid attestation
        let result = accept_or_verify(&envelope_with_sig, &policy, &verifier, &crs.htau, &pk);
        assert!(result.is_ok(), "Valid attestation should be accepted");
    }
    
    #[test]
    fn test_accept_or_verify_fallback_to_crypto() {
        let mut rng = thread_rng();
        
        // Setup dealer and keys
        let batch_size = 4;
        let n = 8;
        let mut dealer = Dealer::<E>::new(batch_size, n, n / 2 - 1);
        let (crs, _) = dealer.setup(&mut rng);
        let pk = dealer.get_pk();
        
        // Create test ciphertext
        let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
        let msg = [1u8; 32];
        let x = tx_domain.group_gen;
        let hid = G1::rand(&mut rng);
        let ct = encrypt::<E>(msg, x, hid, crs.htau, pk, &mut rng);
        
        // Create envelope without attestation (should fallback to crypto verify)
        let envelope = Envelope {
            eid: EpochId(1),
            ct: ct.clone(),
            att: None,
        };
        
        let policy = AcceptancePolicy {
            max_skew_ms: 60000,
            allowlisted_measurements: vec![],
            dev_mode: true,
        };
        
        let verifier = DevAttestationVerifier {
            dev_pubkey: vec![0; 32], // Dummy key, won't be used
        };
        
        // Test: should fallback to cryptographic verification and succeed
        let result = accept_or_verify(&envelope, &policy, &verifier, &crs.htau, &pk);
        assert!(result.is_ok(), "Should fallback to crypto verification successfully");
    }
    
    #[test]
    fn test_reject_invalid_attestation() {
        let mut rng = thread_rng();
        
        // Setup dealer and keys
        let batch_size = 4;
        let n = 8;
        let mut dealer = Dealer::<E>::new(batch_size, n, n / 2 - 1);
        let (crs, _) = dealer.setup(&mut rng);
        let pk = dealer.get_pk();
        
        // Create test ciphertext
        let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
        let msg = [1u8; 32];
        let x = tx_domain.group_gen;
        let hid = G1::rand(&mut rng);
        let ct = encrypt::<E>(msg, x, hid, crs.htau, pk, &mut rng);
        
        // Create envelope with invalid signature
        let envelope = Envelope {
            eid: EpochId(1),
            ct: ct.clone(),
            att: Some(IngressAttestation {
                sig: vec![0; 64], // Invalid signature
                quote: Vec::new(),
                ts_unix_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                nonce: rand::random(),
            }),
        };
        
        let policy = AcceptancePolicy {
            max_skew_ms: 60000,
            allowlisted_measurements: vec![],
            dev_mode: true,
        };
        
        let verifier = DevAttestationVerifier {
            dev_pubkey: vec![0; 32], // Some key
        };
        
        // Test: should reject invalid attestation but fallback to crypto verify should succeed
        let result = accept_or_verify(&envelope, &policy, &verifier, &crs.htau, &pk);
        assert!(result.is_ok(), "Should fallback to crypto verification after attestation failure");
    }
}
