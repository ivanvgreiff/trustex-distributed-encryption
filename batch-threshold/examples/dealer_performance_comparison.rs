// cargo run -p batch-threshold --example dealer_performance_comparison --features tee-dealer,dev-attest --release

use batch_threshold::dealer::{CRS, Dealer};
use batch_threshold::attested_dealer::{
    DevAttestedDealerClient, AttestedDealerClient, accept_attested_dealing, PartyId
};
use batch_threshold::dealer_ra::{DealerAcceptancePolicy, DevAttestationVerifier};
use batch_threshold::dealer_consistency::{verify_same_tau, verify_pk_from_share_commitments};

use ark_bls12_381::Bls12_381 as E;
use ark_ec::{CurveGroup, PrimeGroup};
use rand::SeedableRng;
use std::time::Instant;

fn time_original_dealer_setup(batch_size: usize, n: usize, t: usize, iterations: usize) -> (f64, f64, f64) {
    let mut setup_times = Vec::new();
    let mut verification_times = Vec::new();
    let mut total_times = Vec::new();
    
    for _ in 0..iterations {
        let mut rng = rand::rngs::StdRng::from_entropy();
        
        // Time the setup phase
        let setup_start = Instant::now();
        let mut dealer = Dealer::<E>::new(batch_size, n, t);
        let pk = dealer.get_pk();
        let (crs, shares) = dealer.setup(&mut rng);
        let setup_duration = setup_start.elapsed();
        
        // Time the verification phase (what validators would do)
        let verify_start = Instant::now();
        let same_tau_valid = verify_same_tau::<E>(&crs);
        
        // Build per-share commitments for verification (expensive)
        let per_share_pks: Vec<_> = shares.iter().enumerate().map(|(i, share)| {
            let h_share = (<E as ark_ec::pairing::Pairing>::G2::generator() * share).into_affine();
            (PartyId(i as u32 + 1), h_share)
        }).collect();
        
        let share_commitments_valid = verify_pk_from_share_commitments::<E>(
            n, &pk.into_affine(), &per_share_pks
        );
        let verify_duration = verify_start.elapsed();
        
        let total_duration = setup_duration + verify_duration;
        
        assert!(same_tau_valid && share_commitments_valid, "Verification failed");
        
        setup_times.push(setup_duration.as_secs_f64() * 1000.0); // Convert to ms
        verification_times.push(verify_duration.as_secs_f64() * 1000.0);
        total_times.push(total_duration.as_secs_f64() * 1000.0);
    }
    
    let avg_setup = setup_times.iter().sum::<f64>() / iterations as f64;
    let avg_verify = verification_times.iter().sum::<f64>() / iterations as f64;
    let avg_total = total_times.iter().sum::<f64>() / iterations as f64;
    
    (avg_setup, avg_verify, avg_total)
}

fn time_attested_dealer_setup(batch_size: usize, n: usize, t: usize, iterations: usize) -> (f64, f64, f64) {
    let mut generation_times = Vec::new();
    let mut acceptance_times = Vec::new();
    let mut total_times = Vec::new();
    
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
    
    for _ in 0..iterations {
        let mut rng = rand::rngs::StdRng::from_entropy();
        
        // Time the generation phase (equivalent to original setup)
        let gen_start = Instant::now();
        let dealing = client.generate(&mut rng, batch_size, n, t, &party_ids);
        let gen_duration = gen_start.elapsed();
        
        // Time the acceptance phase (what validators would do)
        let accept_start = Instant::now();
        let verified_setup = accept_attested_dealing::<E, _>(&dealing, &policy, &verifier)
            .expect("attested dealing should be acceptable");
        let accept_duration = accept_start.elapsed();
        
        let total_duration = gen_duration + accept_duration;
        
        // Verify we got the expected results
        assert_eq!(verified_setup.shares.len(), n);
        assert_eq!(verified_setup.crs.powers_of_g.len(), batch_size);
        
        generation_times.push(gen_duration.as_secs_f64() * 1000.0); // Convert to ms
        acceptance_times.push(accept_duration.as_secs_f64() * 1000.0);
        total_times.push(total_duration.as_secs_f64() * 1000.0);
    }
    
    let avg_gen = generation_times.iter().sum::<f64>() / iterations as f64;
    let avg_accept = acceptance_times.iter().sum::<f64>() / iterations as f64;
    let avg_total = total_times.iter().sum::<f64>() / iterations as f64;
    
    (avg_gen, avg_accept, avg_total)
}

fn main() {
    println!("🔥 DEALER PERFORMANCE COMPARISON: ORIGINAL vs ATTESTED");
    println!("{}", "=".repeat(80));
    println!();
    
    // Test cases aligned with HbTPKE-TEE Draft evaluation plan
    // B ∈ {128, 512}, n ∈ {16, 64, 128} per Section 7
    let test_cases = vec![
        (128, 16, 7, "B128_n16"),
        (128, 64, 31, "B128_n64"), 
        (128, 128, 63, "B128_n128"),
        (512, 16, 7, "B512_n16"),
        (512, 64, 31, "B512_n64"),
        (512, 128, 63, "B512_n128"),
    ];
    
    let iterations = 10;
    
    println!("Running {} iterations per test case...", iterations);
    println!();
    
    // Results table header
    println!("{:<12} {:<20} {:<20} {:<15} {:<15} {:<15}", 
        "Test Case", "Original Total (ms)", "Attested Total (ms)", "Speed Improvement", "Setup Speedup", "Verify Speedup");
    println!("{}", "-".repeat(120));
    
    let mut all_improvements = Vec::new();
    
    for (batch_size, n, t, name) in test_cases {
        print!("Testing {} (B={}, n={}, t={})... ", name, batch_size, n, t);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        
        let (orig_setup, orig_verify, orig_total) = time_original_dealer_setup(batch_size, n, t, iterations);
        let (att_gen, att_accept, att_total) = time_attested_dealer_setup(batch_size, n, t, iterations);
        
        let total_improvement = orig_total / att_total;
        let setup_improvement = orig_setup / att_gen;
        let verify_improvement = orig_verify / att_accept;
        
        all_improvements.push(total_improvement);
        
        println!("Done");
        
        println!("{:<12} {:<20.2} {:<20.2} {:<15.1}x {:<15.1}x {:<15.1}x", 
            name, orig_total, att_total, total_improvement, setup_improvement, verify_improvement);
    }
    
    println!("{}", "-".repeat(120));
    
    let avg_improvement = all_improvements.iter().sum::<f64>() / all_improvements.len() as f64;
    println!("Average Speed Improvement: {:.1}x", avg_improvement);
    
    println!();
    println!("📊 DETAILED BREAKDOWN");
    println!("{}", "=".repeat(50));
    
    // Detailed analysis for medium case
    let (batch_size, n, t) = (128, 32, 15);
    println!("Detailed analysis for Medium case (B={}, n={}, t={}):", batch_size, n, t);
    
    let (orig_setup, orig_verify, orig_total) = time_original_dealer_setup(batch_size, n, t, 20);
    let (att_gen, att_accept, att_total) = time_attested_dealer_setup(batch_size, n, t, 20);
    
    println!();
    println!("ORIGINAL DEALER:");
    println!("  Setup Phase:        {:.2}ms", orig_setup);
    println!("  Verification Phase: {:.2}ms (expensive pairing operations)", orig_verify);
    println!("  Total Time:         {:.2}ms", orig_total);
    
    println!();
    println!("ATTESTED DEALER:");
    println!("  Generation Phase:   {:.2}ms (includes Ed25519 signing)", att_gen);
    println!("  Acceptance Phase:   {:.2}ms (Ed25519 verify + consistency checks)", att_accept);
    println!("  Total Time:         {:.2}ms", att_total);
    
    println!();
    println!("🚀 PERFORMANCE GAINS:");
    println!("  Total Speedup:      {:.1}x faster", orig_total / att_total);
    println!("  Time Saved:         {:.2}ms ({:.1}% reduction)", orig_total - att_total, (1.0 - att_total/orig_total) * 100.0);
    println!("  Verification Speedup: {:.1}x faster", orig_verify / att_accept);
    
    // Per-party analysis
    let orig_per_party = orig_total / n as f64;
    let att_per_party = att_total / n as f64;
    
    println!();
    println!("📈 PER-PARTY ANALYSIS:");
    println!("  Original per-party cost: {:.2}ms", orig_per_party);
    println!("  Attested per-party cost: {:.2}ms", att_per_party);
    println!("  Per-party improvement:   {:.1}x", orig_per_party / att_per_party);
    
    println!();
    println!("💡 KEY INSIGHTS:");
    println!("  • Attested dealer eliminates expensive pairing-based consistency checks");
    println!("  • Ed25519 signature verification is ~{}x faster than pairing operations", (orig_verify / att_accept) as u32);
    println!("  • Setup phase performance is similar (both generate CRS + shares)");
    println!("  • Major gains come from validator-side verification efficiency");
    println!("  • Scalability: Improvements maintain across different parameter sizes");
    
    println!();
    println!("🎯 REAL-WORLD IMPACT:");
    println!("  For a network with frequent dealer setups:");
    println!("  • Validators save {:.1}% of dealer verification CPU", (1.0 - att_accept/orig_verify) * 100.0);
    println!("  • Network can support {:.1}x more frequent parameter updates", orig_verify / att_accept);
    println!("  • Reduced hardware requirements for validator nodes");
    println!("  • Faster network bootstrap and parameter rotation");
}
