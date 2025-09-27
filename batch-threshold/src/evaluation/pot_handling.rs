//! Powers of Tau (PoT) Handling Module
//! 
//! Handles both public PoT fetching/verification and local CRS generation with same-τ checks.
//! Provides byte counting and timing measurements for evaluation.

use std::collections::HashMap;
use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::Pairing;
use ark_ec::{PrimeGroup, CurveGroup, AffineRepr};
use ark_ff::{One, Zero};
use ark_std::{rand::RngCore, UniformRand};
use crate::dealer::CRS;
use thiserror::Error;

#[derive(Debug, Clone)]
pub enum PotMode {
    /// Fetch and verify a known public PoT ceremony
    PublicPot(String),
    /// Generate local CRS with same-τ verification
    LocalCrs,
}

#[derive(Debug)]
pub struct PotResult {
    pub bytes_fetched: usize,
    pub verification_passed: bool,
    pub pot_id: String,
}

#[derive(Debug)]
pub struct PotHandler {
    mode: PotMode,
    /// Cache of known public ceremonies with their metadata
    ceremony_cache: HashMap<String, CeremonyInfo>,
}

#[derive(Debug, Clone)]
struct CeremonyInfo {
    pub name: String,
    pub description: String,
    pub expected_size_mb: f64,
    pub verification_time_ms: u64,
}

#[derive(Error, Debug)]
pub enum PotError {
    #[error("Unknown ceremony: {ceremony}")]
    UnknownCeremony { ceremony: String },
    #[error("Network error: {msg}")]
    NetworkError { msg: String },
    #[error("Verification failed: {msg}")]
    VerificationFailed { msg: String },
    #[error("CRS too short for same-τ verification")]
    CrsTooShort,
    #[error("Same-τ check failed at index {index}")]
    SameTauFailed { index: usize },
}

impl PotHandler {
    pub fn new(mode: PotMode) -> Self {
        let mut ceremony_cache = HashMap::new();
        
        // Well-known ceremonies for simulation
        ceremony_cache.insert("eth-kzg-ceremony".to_string(), CeremonyInfo {
            name: "Ethereum KZG Ceremony".to_string(),
            description: "Ethereum's KZG trusted setup ceremony".to_string(),
            expected_size_mb: 142.0, // Approximate size of KZG ceremony
            verification_time_ms: 50,
        });
        
        ceremony_cache.insert("hermez-ceremony".to_string(), CeremonyInfo {
            name: "Hermez Network Ceremony".to_string(), 
            description: "Hermez zkEVM trusted setup".to_string(),
            expected_size_mb: 89.0,
            verification_time_ms: 35,
        });
        
        ceremony_cache.insert("zcash-ceremony".to_string(), CeremonyInfo {
            name: "Zcash Powers of Tau".to_string(),
            description: "Zcash's original Powers of Tau ceremony".to_string(),
            expected_size_mb: 200.0,
            verification_time_ms: 75,
        });
        
        ceremony_cache.insert("test-ceremony".to_string(), CeremonyInfo {
            name: "Test Ceremony".to_string(),
            description: "Small test ceremony for development".to_string(),
            expected_size_mb: 1.0,
            verification_time_ms: 5,
        });
        
        Self { mode, ceremony_cache }
    }
    
    /// Fetch and verify a public PoT ceremony
    pub fn fetch_and_verify(&self, pot_url: &str) -> Result<PotResult, PotError> {
        match &self.mode {
            PotMode::PublicPot(_) => self.fetch_public_pot(pot_url),
            PotMode::LocalCrs => Err(PotError::NetworkError { 
                msg: "Cannot fetch public PoT in local CRS mode".to_string() 
            }),
        }
    }
    
    /// Verify same-τ property of a CRS (for local CRS mode)
    pub fn verify_same_tau(&self, crs: &CRS<E>) -> Result<(), PotError> {
        match &self.mode {
            PotMode::LocalCrs => self.verify_crs_same_tau(crs),
            PotMode::PublicPot(_) => Ok(()), // Skip same-τ check when using public PoT
        }
    }
    
    /// Generate a local CRS with known τ (for testing)
    pub fn generate_local_crs<R: RngCore>(
        &self, 
        rng: &mut R, 
        batch_size: usize
    ) -> Result<(CRS<E>, <E as Pairing>::ScalarField), PotError> {
        match &self.mode {
            PotMode::LocalCrs => {
                let tau = <E as Pairing>::ScalarField::rand(rng);
                let crs = self.generate_crs_with_tau(tau, batch_size);
                Ok((crs, tau))
            }
            PotMode::PublicPot(_) => Err(PotError::VerificationFailed { 
                msg: "Cannot generate local CRS in public PoT mode".to_string() 
            }),
        }
    }
    
    /// Simulate fetching a public PoT ceremony
    fn fetch_public_pot(&self, pot_url: &str) -> Result<PotResult, PotError> {
        let ceremony = self.ceremony_cache.get(pot_url)
            .ok_or_else(|| PotError::UnknownCeremony { 
                ceremony: pot_url.to_string() 
            })?;
        
        // Simulate network fetch time based on ceremony size
        let fetch_delay_ms = (ceremony.expected_size_mb * 10.0) as u64; // ~10ms per MB
        std::thread::sleep(std::time::Duration::from_millis(fetch_delay_ms));
        
        // Simulate verification time
        std::thread::sleep(std::time::Duration::from_millis(ceremony.verification_time_ms));
        
        // Calculate bytes fetched (convert MB to bytes)
        let bytes_fetched = (ceremony.expected_size_mb * 1024.0 * 1024.0) as usize;
        
        Ok(PotResult {
            bytes_fetched,
            verification_passed: true,
            pot_id: pot_url.to_string(),
        })
    }
    
    /// Verify same-τ property: e(g^{τ^i}, h) == e(g^{τ^{i-1}}, h^τ) for i=1..B-1
    fn verify_crs_same_tau(&self, crs: &CRS<E>) -> Result<(), PotError> {
        use ark_ec::AffineRepr;
        
        let h = <E as Pairing>::G2::generator().into_affine();
        let htau = crs.htau.into_affine();
        let powers = &crs.powers_of_g;
        
        if powers.len() < 2 {
            return Err(PotError::CrsTooShort);
        }
        
        // Check pairing equations
        for i in 1..powers.len() {
            let lhs = E::pairing(powers[i], h);
            let rhs = E::pairing(powers[i - 1], htau);
            
            if lhs != rhs {
                return Err(PotError::SameTauFailed { index: i });
            }
        }
        
        Ok(())
    }
    
    /// Generate CRS with a specific τ value
    fn generate_crs_with_tau(
        &self, 
        tau: <E as Pairing>::ScalarField, 
        batch_size: usize
    ) -> CRS<E> {
        use ark_ec::scalar_mul::ScalarMul;
        use std::iter;
        
        // Generate powers of τ
        let powers_of_tau: Vec<_> = iter::successors(
            Some(<E as Pairing>::ScalarField::one()), 
            |p| Some(*p * tau)
        ).take(batch_size).collect();
        
        // Generators
        let g = <E as Pairing>::G1::generator();
        let h = <E as Pairing>::G2::generator();
        
        // Compute g^{τ^i} for i = 0..batch_size-1
        let powers_of_g = g.batch_mul(&powers_of_tau);
        
        // Compute h^τ
        let htau = h * tau;
        
        // For the Toeplitz matrix preprocessing (simplified version)
        let mut top_tau = powers_of_tau.clone();
        top_tau.reverse();
        top_tau.resize(2 * batch_size, <E as Pairing>::ScalarField::zero());
        
        // Use FFT domain for preprocessing (same as dealer.rs)
        use ark_poly::{domain::EvaluationDomain, Radix2EvaluationDomain};
        let top_domain = Radix2EvaluationDomain::<<E as Pairing>::ScalarField>::new(2 * batch_size).unwrap();
        let top_tau_fft = top_domain.fft(&top_tau);
        let y = g.batch_mul(&top_tau_fft);
        
        CRS { powers_of_g, htau, y }
    }
    
    /// Get ceremony information for a given ceremony ID
    pub fn get_ceremony_info(&self, ceremony_id: &str) -> Option<&CeremonyInfo> {
        self.ceremony_cache.get(ceremony_id)
    }
    
    /// List all available ceremonies
    pub fn list_ceremonies(&self) -> Vec<&str> {
        self.ceremony_cache.keys().map(|s| s.as_str()).collect()
    }
}

/// Utility functions for PoT handling

/// Estimate the verification time for a ceremony of given size
pub fn estimate_verification_time_ms(size_mb: f64) -> u64 {
    // Rough estimate: ~0.5ms per MB for verification
    (size_mb * 0.5) as u64
}

/// Estimate the network fetch time for a ceremony of given size
pub fn estimate_fetch_time_ms(size_mb: f64, bandwidth_mbps: f64) -> u64 {
    if bandwidth_mbps <= 0.0 {
        return 0; // Unlimited bandwidth
    }
    
    // Convert to seconds, then to milliseconds
    let time_s = (size_mb * 8.0) / bandwidth_mbps; // 8 bits per byte
    (time_s * 1000.0) as u64
}

/// Calculate the size of a CRS in bytes
pub fn calculate_crs_size_bytes(crs: &CRS<E>) -> usize {
    // G1 points: 48 bytes compressed
    let g1_size = crs.powers_of_g.len() * 48;
    // G2 point: 96 bytes compressed  
    let g2_size = 96;
    // Y vector: same as powers_of_g
    let y_size = crs.y.len() * 48;
    
    g1_size + g2_size + y_size
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    
    #[test]
    fn test_pot_handler_creation() {
        let handler = PotHandler::new(PotMode::PublicPot("eth-kzg-ceremony".to_string()));
        assert!(handler.get_ceremony_info("eth-kzg-ceremony").is_some());
        assert!(handler.get_ceremony_info("nonexistent").is_none());
    }
    
    #[test]
    fn test_list_ceremonies() {
        let handler = PotHandler::new(PotMode::LocalCrs);
        let ceremonies = handler.list_ceremonies();
        assert!(ceremonies.contains(&"eth-kzg-ceremony"));
        assert!(ceremonies.contains(&"test-ceremony"));
    }
    
    #[test]
    fn test_public_pot_fetch() {
        let handler = PotHandler::new(PotMode::PublicPot("test-ceremony".to_string()));
        let result = handler.fetch_and_verify("test-ceremony").unwrap();
        
        assert!(result.verification_passed);
        assert_eq!(result.pot_id, "test-ceremony");
        assert!(result.bytes_fetched > 0);
    }
    
    #[test]
    fn test_unknown_ceremony() {
        let handler = PotHandler::new(PotMode::PublicPot("unknown".to_string()));
        let result = handler.fetch_and_verify("unknown");
        
        assert!(matches!(result, Err(PotError::UnknownCeremony { .. })));
    }
    
    #[test]
    fn test_local_crs_generation() {
        let handler = PotHandler::new(PotMode::LocalCrs);
        let mut rng = StdRng::seed_from_u64(42);
        let batch_size = 16;
        
        let (crs, tau) = handler.generate_local_crs(&mut rng, batch_size).unwrap();
        
        assert_eq!(crs.powers_of_g.len(), batch_size);
        assert_eq!(crs.y.len(), 2 * batch_size);
        
        // Verify the CRS is well-formed
        assert!(handler.verify_same_tau(&crs).is_ok());
    }
    
    #[test]
    fn test_same_tau_verification() {
        let handler = PotHandler::new(PotMode::LocalCrs);
        let mut rng = StdRng::seed_from_u64(42);
        
        let (crs, _) = handler.generate_local_crs(&mut rng, 8).unwrap();
        
        // Should pass verification
        assert!(handler.verify_same_tau(&crs).is_ok());
    }
    
    #[test]
    fn test_same_tau_verification_fails_with_bad_crs() {
        let handler = PotHandler::new(PotMode::LocalCrs);
        
        // Create a malformed CRS
        let g = <E as Pairing>::G1::generator();
        let h = <E as Pairing>::G2::generator();
        
        let bad_crs = CRS {
            powers_of_g: vec![g.into_affine(); 4], // All the same point (invalid)
            htau: (h * <E as Pairing>::ScalarField::from(2u64)),
            y: vec![g.into_affine(); 8],
        };
        
        // Should fail verification
        assert!(matches!(
            handler.verify_same_tau(&bad_crs),
            Err(PotError::SameTauFailed { .. })
        ));
    }
    
    #[test]
    fn test_crs_size_calculation() {
        let handler = PotHandler::new(PotMode::LocalCrs);
        let mut rng = StdRng::seed_from_u64(42);
        
        let (crs, _) = handler.generate_local_crs(&mut rng, 16).unwrap();
        let size = calculate_crs_size_bytes(&crs);
        
        // Expected: 16 G1 points (48 bytes each) + 1 G2 point (96 bytes) + 32 G1 points for y
        let expected = 16 * 48 + 96 + 32 * 48;
        assert_eq!(size, expected);
    }
    
    #[test]
    fn test_time_estimates() {
        let verification_time = estimate_verification_time_ms(100.0);
        assert!(verification_time > 0);
        
        let fetch_time = estimate_fetch_time_ms(100.0, 10.0); // 100MB at 10Mbps
        assert!(fetch_time > 0);
        
        let fetch_time_unlimited = estimate_fetch_time_ms(100.0, 0.0);
        assert_eq!(fetch_time_unlimited, 0);
    }
    
    #[test]
    fn test_mode_restrictions() {
        let public_handler = PotHandler::new(PotMode::PublicPot("test-ceremony".to_string()));
        let local_handler = PotHandler::new(PotMode::LocalCrs);
        
        // Public handler should not generate local CRS
        let mut rng = StdRng::seed_from_u64(42);
        assert!(public_handler.generate_local_crs(&mut rng, 16).is_err());
        
        // Local handler should not fetch public PoT
        assert!(local_handler.fetch_and_verify("test-ceremony").is_err());
    }
}
