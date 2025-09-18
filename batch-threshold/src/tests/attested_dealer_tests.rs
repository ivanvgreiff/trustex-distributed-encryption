#[cfg(all(test, feature = "tee-dealer", feature = "dev-attest"))]
mod attested_dealer_tests {
    use crate::attested_dealer::{
        DevAttestedDealerClient, AttestedDealerClient, accept_attested_dealing, PartyId,
        AttestedDealerError
    };
    use crate::dealer_ra::{DealerAcceptancePolicy, DevAttestationVerifier};
    use ark_bls12_381::Bls12_381 as E;
    use rand::SeedableRng;

    #[test]
    fn accept_valid_dealing_dev() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let measurement = [7u8; 32];
        let client = DevAttestedDealerClient::<E>::new(signing, measurement);
        let mut rng = rand::rngs::StdRng::from_entropy();

        let n = 4usize; 
        let t = 1usize; 
        let batch_size = 8usize;
        let party_ids = (1..=n as u32).map(PartyId).collect::<Vec<_>>();
        let dealing = client.generate(&mut rng, batch_size, n, t, &party_ids);

        let policy = DealerAcceptancePolicy { 
            max_skew_ms: 60_000, 
            allowlisted_measurements: vec![measurement], 
            dev_mode: true 
        };
        let verifier = DevAttestationVerifier;
        let verified_setup = accept_attested_dealing::<E, _>(&dealing, &policy, &verifier).unwrap();
        
        assert_eq!(verified_setup.shares.len(), n);
        assert_eq!(verified_setup.crs.powers_of_g.len(), batch_size);
        assert_eq!(verified_setup.commitments.per_share_pks.len(), n);
    }

    #[test]
    fn reject_wrong_measurement() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let measurement = [7u8; 32];
        let client = DevAttestedDealerClient::<E>::new(signing, measurement);
        let mut rng = rand::rngs::StdRng::from_entropy();

        let n = 4usize; 
        let t = 1usize; 
        let batch_size = 8usize;
        let party_ids = (1..=n as u32).map(PartyId).collect::<Vec<_>>();
        let dealing = client.generate(&mut rng, batch_size, n, t, &party_ids);

        // Policy with different measurement
        let wrong_measurement = [42u8; 32];
        let policy = DealerAcceptancePolicy { 
            max_skew_ms: 60_000, 
            allowlisted_measurements: vec![wrong_measurement], 
            dev_mode: true 
        };
        let verifier = DevAttestationVerifier;
        
        let result = accept_attested_dealing::<E, _>(&dealing, &policy, &verifier);
        assert!(matches!(result, Err(AttestedDealerError::Attestation(_))));
    }

    #[test]
    fn reject_dev_mode_disabled() {
        let signing = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let measurement = [7u8; 32];
        let client = DevAttestedDealerClient::<E>::new(signing, measurement);
        let mut rng = rand::rngs::StdRng::from_entropy();

        let n = 4usize; 
        let t = 1usize; 
        let batch_size = 8usize;
        let party_ids = (1..=n as u32).map(PartyId).collect::<Vec<_>>();
        let dealing = client.generate(&mut rng, batch_size, n, t, &party_ids);

        // Policy with dev_mode disabled
        let policy = DealerAcceptancePolicy { 
            max_skew_ms: 60_000, 
            allowlisted_measurements: vec![measurement], 
            dev_mode: false  // disabled
        };
        let verifier = DevAttestationVerifier;
        
        let result = accept_attested_dealing::<E, _>(&dealing, &policy, &verifier);
        assert!(matches!(result, Err(AttestedDealerError::Attestation(_))));
    }

    #[test]
    fn test_crs_same_tau_check() {
        use crate::dealer_consistency::verify_same_tau;
        use crate::dealer::Dealer;
        
        let mut rng = rand::rngs::StdRng::from_entropy();
        let mut dealer = Dealer::<E>::new(8, 4, 2);
        let (crs, _) = dealer.setup(&mut rng);
        
        // Valid CRS should pass same-tau check
        assert!(verify_same_tau::<E>(&crs));
    }

    #[test]
    fn test_share_commitment_verification() {
        use crate::dealer_consistency::verify_pk_from_share_commitments;
        use crate::dealer::Dealer;
        use ark_ec::{CurveGroup, PrimeGroup};
        
        let mut rng = rand::rngs::StdRng::from_entropy();
        let mut dealer = Dealer::<E>::new(8, 4, 2);
        let pk = dealer.get_pk();
        let (_, shares) = dealer.setup(&mut rng);
        
        // Build per-share commitments
        let per_share_pks: Vec<_> = shares.iter().enumerate().map(|(i, share)| {
            let h_share = (<E as ark_ec::pairing::Pairing>::G2::generator() * share).into_affine();
            (PartyId(i as u32 + 1), h_share)
        }).collect();
        
        // Should verify correctly
        assert!(verify_pk_from_share_commitments::<E>(
            shares.len(), 
            &pk.into_affine(), 
            &per_share_pks
        ));
    }
}
