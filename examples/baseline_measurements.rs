use std::collections::BTreeMap;
use std::time::Instant;

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{end_timer, start_timer, UniformRand};
use batch_threshold::{
    dealer::Dealer,
    decryption::{aggregate_partial_decryptions, decrypt_all, SecretKey},
    encryption::{encrypt, Ciphertext},
};

type E = Bls12_381;
type Fr = <E as Pairing>::ScalarField;
type G1 = <E as Pairing>::G1;

fn main() {
    println!("=== BTE++ Baseline Measurements ===\n");
    
    // Parameters matching paper evaluation
    let batch_sizes = vec![128, 256, 512]; // ~500 tx target
    let n = 16; // committee size
    let t = 7;  // threshold (t+1 = 8 parties needed)
    
    for &batch_size in &batch_sizes {
        println!("📊 Batch Size: {} transactions", batch_size);
        println!("👥 Committee: n={}, threshold t={} (need {} parties)", n, t, t+1);
        println!("{}", "=".repeat(50));
        
        measure_ciphertext_sizes(batch_size, n, t);
        measure_communication_overhead(batch_size, n, t);
        measure_timing_breakdown(batch_size, n, t);
        profile_verification_hotspot(batch_size, n, t);
        
        println!("\n");
    }
}

fn measure_ciphertext_sizes(batch_size: usize, n: usize, t: usize) {
    println!("🔍 Ciphertext Size Measurements");
    
    let mut rng = ark_std::test_rng();
    let mut dealer = Dealer::<E>::new(batch_size, n, t);
    let (crs, _) = dealer.setup(&mut rng);
    let pk = dealer.get_pk();
    
    let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
    let msg = [1u8; 32];
    let hid = G1::rand(&mut rng);
    
    // Create sample ciphertext
    let x = tx_domain.group_gen;
    let ct = encrypt::<E>(msg, x, hid, crs.htau, pk, &mut rng);
    
    // Measure serialized sizes
    let mut compressed_bytes = Vec::new();
    let mut uncompressed_bytes = Vec::new();
    
    ct.serialize_compressed(&mut compressed_bytes).unwrap();
    ct.serialize_uncompressed(&mut uncompressed_bytes).unwrap();
    
    println!("  • Compressed ciphertext:   {} bytes", compressed_bytes.len());
    println!("  • Uncompressed ciphertext: {} bytes", uncompressed_bytes.len());
    println!("  • Target from paper:       ~466 bytes");
    
    // Verify we can deserialize
    let _ct_recovered: Ciphertext<E> = CanonicalDeserialize::deserialize_compressed(&compressed_bytes[..]).unwrap();
    println!("  ✓ Serialization/deserialization verified");
}

fn measure_communication_overhead(batch_size: usize, n: usize, t: usize) {
    println!("📡 Communication Overhead Measurements");
    
    let mut rng = ark_std::test_rng();
    let mut dealer = Dealer::<E>::new(batch_size, n, t);
    let (crs, sk_shares) = dealer.setup(&mut rng);
    let pk = dealer.get_pk();
    
    // Create secret keys for committee
    let mut secret_keys = Vec::new();
    for i in 0..n {
        secret_keys.push(SecretKey::new(sk_shares[i]));
    }
    
    let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
    let msg = [1u8; 32];
    let hid = G1::rand(&mut rng);
    
    // Generate batch of ciphertexts
    let mut ct: Vec<Ciphertext<E>> = Vec::new();
    for x in tx_domain.elements() {
        ct.push(encrypt::<E>(msg, x, hid, crs.htau, pk, &mut rng));
    }
    
    // Measure partial decryption result size
    let partial_decryption = secret_keys[0].partial_decrypt(&ct, hid, pk, &crs);
    
    let mut pd_compressed = Vec::new();
    let mut pd_uncompressed = Vec::new();
    
    partial_decryption.serialize_compressed(&mut pd_compressed).unwrap();
    partial_decryption.serialize_uncompressed(&mut pd_uncompressed).unwrap();
    
    println!("  • Partial decryption (compressed):   {} bytes", pd_compressed.len());
    println!("  • Partial decryption (uncompressed): {} bytes", pd_uncompressed.len());
    println!("  • Target from paper:                 ~48 bytes per party");
    
    // Total communication for threshold
    let total_comm = pd_compressed.len() * (t + 1);
    println!("  • Total communication ({} parties): {} bytes", t + 1, total_comm);
}

fn measure_timing_breakdown(batch_size: usize, n: usize, t: usize) {
    println!("⏱️  Timing Breakdown Measurements");
    
    let mut rng = ark_std::test_rng();
    let mut dealer = Dealer::<E>::new(batch_size, n, t);
    
    // Measure setup time
    let setup_timer = start_timer!(|| "Setup");
    let (crs, sk_shares) = dealer.setup(&mut rng);
    let pk = dealer.get_pk();
    end_timer!(setup_timer);
    
    // Create secret keys
    let mut secret_keys = Vec::new();
    for i in 0..n {
        secret_keys.push(SecretKey::new(sk_shares[i]));
    }
    
    let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
    let msg = [1u8; 32];
    let hid = G1::rand(&mut rng);
    
    // Measure encryption time (single transaction)
    let encrypt_timer = Instant::now();
    let x = tx_domain.group_gen;
    let _single_ct = encrypt::<E>(msg, x, hid, crs.htau, pk, &mut rng);
    let encrypt_time = encrypt_timer.elapsed();
    println!("  • Single encryption time: {:?}", encrypt_time);
    
    // Generate full batch of ciphertexts
    let batch_encrypt_timer = Instant::now();
    let mut ct: Vec<Ciphertext<E>> = Vec::new();
    for x in tx_domain.elements() {
        ct.push(encrypt::<E>(msg, x, hid, crs.htau, pk, &mut rng));
    }
    let batch_encrypt_time = batch_encrypt_timer.elapsed();
    println!("  • Batch encryption time ({} tx): {:?}", batch_size, batch_encrypt_time);
    
    // Measure partial decryption time
    let partial_decrypt_timer = Instant::now();
    let mut partial_decryptions: BTreeMap<usize, G1> = BTreeMap::new();
    for i in 0..=t {  // t+1 parties
        let pd = secret_keys[i].partial_decrypt(&ct, hid, pk, &crs);
        partial_decryptions.insert(i + 1, pd);
    }
    let partial_decrypt_time = partial_decrypt_timer.elapsed();
    println!("  • Partial decryption ({} parties): {:?}", t + 1, partial_decrypt_time);
    println!("  • Target from paper: ~3.2s per partial decryption");
    
    // Measure aggregation and final decryption
    let final_decrypt_timer = Instant::now();
    let sigma = aggregate_partial_decryptions(&partial_decryptions);
    let messages = decrypt_all(sigma, &ct, hid, &crs);
    let final_decrypt_time = final_decrypt_timer.elapsed();
    println!("  • Aggregation + final decryption: {:?}", final_decrypt_time);
    println!("  • Target from paper: ~3.0s to combine ~500 tx");
    
    // Verify correctness
    for i in 0..batch_size {
        assert_eq!(msg, messages[i]);
    }
    println!("  ✓ All messages decrypted correctly");
}

fn profile_verification_hotspot(batch_size: usize, n: usize, t: usize) {
    println!("🔥 SE-NIZK Verification Hotspot Profiling");
    
    let mut rng = ark_std::test_rng();
    let mut dealer = Dealer::<E>::new(batch_size, n, t);
    let (crs, sk_shares) = dealer.setup(&mut rng);
    let pk = dealer.get_pk();
    
    let secret_key = SecretKey::new(sk_shares[0]);
    let tx_domain = Radix2EvaluationDomain::<Fr>::new(batch_size).unwrap();
    let msg = [1u8; 32];
    let hid = G1::rand(&mut rng);
    
    // Generate batch of ciphertexts
    let mut ct: Vec<Ciphertext<E>> = Vec::new();
    for x in tx_domain.elements() {
        ct.push(encrypt::<E>(msg, x, hid, crs.htau, pk, &mut rng));
    }
    
    // Time just the verification calls within partial_decrypt
    println!("  • Profiling verification calls in partial_decrypt...");
    
    // Custom timing: verify each ciphertext individually
    let verification_timer = Instant::now();
    for i in 0..batch_size {
        ct[i].verify(crs.htau, pk);  // This is the SE-NIZK verification hotspot
    }
    let verification_time = verification_timer.elapsed();
    
    // Time the full partial_decrypt for comparison
    let full_partial_decrypt_timer = Instant::now();
    let _pd = secret_key.partial_decrypt(&ct, hid, pk, &crs);
    let full_partial_decrypt_time = full_partial_decrypt_timer.elapsed();
    
    let verification_percentage = (verification_time.as_secs_f64() / full_partial_decrypt_time.as_secs_f64()) * 100.0;
    
    println!("  • SE-NIZK verification time: {:?}", verification_time);
    println!("  • Full partial decrypt time: {:?}", full_partial_decrypt_time);
    println!("  • Verification percentage: {:.1}%", verification_percentage);
    println!("  • Target from paper: >99% verification overhead");
    
    if verification_percentage > 90.0 {
        println!("  ✓ Confirmed: SE-NIZK verification dominates timing");
    } else {
        println!("  ⚠️  Verification overhead lower than expected");
    }
}

// Simplified approach: just measure verification vs full partial_decrypt
// We don't need to isolate the computation since verification dominates anyway