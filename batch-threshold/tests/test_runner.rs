//! Test runner for the setup evaluation framework
//! 
//! This file provides integration tests to verify the evaluation framework works correctly.

mod pot_handling;
mod ra_simulation;
mod metrics;
mod simple_attested_setup;

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::Pairing;
use rand::rngs::StdRng;
use rand::SeedableRng;

use batch_threshold::dealer::Dealer;

use pot_handling::{PotHandler, PotMode};
use ra_simulation::{RASimulator, MockQuote};
use metrics::{BaselineMetrics, AttestedMetrics, EvaluationResult, CsvRecord, EvaluationMode, CrsMode};
use simple_attested_setup::{run_attested_setup_crypto_only, DealerInput, AttestedDealing};

/// Global operator step counter for wall-clock measurements
static OP_STEPS: AtomicUsize = AtomicUsize::new(0);

/// Byte counter for network measurements
#[derive(Debug, Default)]
pub struct ByteCounter {
    pub dkg_bytes: usize,
    pub pot_bytes: usize,
    pub total_bytes: usize,
}

impl ByteCounter {
    pub fn add_dkg(&mut self, bytes: usize) {
        self.dkg_bytes += bytes;
        self.total_bytes += bytes;
    }
    
    pub fn add_pot(&mut self, bytes: usize) {
        self.pot_bytes += bytes;
        self.total_bytes += bytes;
    }
    
    pub fn dkg_total_mb(&self) -> f64 {
        self.dkg_bytes as f64 / (1024.0 * 1024.0)
    }
    
    pub fn pot_total_mb(&self) -> f64 {
        self.pot_bytes as f64 / (1024.0 * 1024.0)
    }
    
    pub fn total_mb(&self) -> f64 {
        self.total_bytes as f64 / (1024.0 * 1024.0)
    }
}

/// Network simulation (placeholder for future WAN emulation)
#[derive(Debug)]
pub struct NetworkSim {
    pub latency_ms: u64,
    pub jitter_ms: u64,
    pub rate_mbps: u64,
}

impl NetworkSim {
    pub fn new(latency_ms: u64, jitter_ms: u64, rate_mbps: u64) -> Self {
        Self { latency_ms, jitter_ms, rate_mbps }
    }
    
    /// Apply network delay (placeholder - real implementation would use traffic control)
    pub fn apply_delay(&self) {
        if self.latency_ms > 0 {
            std::thread::sleep(Duration::from_millis(self.latency_ms));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baseline_metrics_creation() {
        // Test creating baseline metrics
        let metrics = BaselineMetrics {
            dealer_dkg_ms: 100,
            pot_pin_verify_ms: 50,
            ceremony_wall_s: 2.5,
            operator_steps: 2,
            bytes_total_mb: 150.0,
            bytes_dkg_mb: 8.0,
            bytes_pot_mb: 142.0,
            audit_evidence_kb: 12.5,
            audit_sha256: "abc123".to_string(),
        };
        
        assert_eq!(metrics.dealer_dkg_ms, 100);
        assert_eq!(metrics.pot_pin_verify_ms, 50);
        assert_eq!(metrics.ceremony_wall_s, 2.5);
        assert_eq!(metrics.operator_steps, 2);
    }
    
    #[test]
    fn test_attested_metrics_creation() {
        // Test creating attested metrics
        let metrics = AttestedMetrics {
            dealer_dkg_ms: 100,
            pot_pin_verify_ms: 50,
            commitments_ms: 25,
            pk_from_commitments_ms: 15,
            transcript_digest_ms: 5,
            same_tau_verify_ms: 0,
            ra_emit_ms: 25,
            ra_verify_ms: 15,
            ceremony_wall_s: 4.5,
            operator_steps: 2,
            attest_publish_s: 0.5,
            bytes_total_mb: 155.0,
            bytes_dkg_mb: 8.0,
            bytes_pot_mb: 142.0,
            audit_evidence_kb: 18.7,
            audit_sha256: "def456".to_string(),
            code_measurement: "789abc".to_string(),
        };
        
        assert_eq!(metrics.dealer_dkg_ms, 100);
        assert_eq!(metrics.ra_emit_ms, 25);
        assert_eq!(metrics.ra_verify_ms, 15);
        assert!(!metrics.code_measurement.is_empty());
    }
    
    #[test]
    fn test_pot_handling() {
        // Test public PoT mode
        let handler = PotHandler::new(PotMode::PublicPot("test-ceremony".to_string()));
        let result = handler.fetch_and_verify("test-ceremony");
        assert!(result.is_ok(), "Test ceremony should be available");
        
        let result = result.unwrap();
        assert!(result.verification_passed, "Verification should pass");
        assert_eq!(result.pot_id, "test-ceremony");
        assert!(result.bytes_fetched > 0, "Should have fetched some bytes");
        
        // Test local CRS mode
        let handler = PotHandler::new(PotMode::LocalCrs);
        let mut rng = StdRng::seed_from_u64(42);
        let result = handler.generate_local_crs(&mut rng, 8);
        assert!(result.is_ok(), "Local CRS generation should succeed");
        
        let (crs, _tau) = result.unwrap();
        assert_eq!(crs.powers_of_g.len(), 8, "Should have correct number of G1 points");
        
        // Verify same-τ property
        let verify_result = handler.verify_same_tau(&crs);
        assert!(verify_result.is_ok(), "Same-τ verification should pass: {:?}", verify_result.err());
    }
    
    #[test]
    fn test_ra_simulation() {
        let simulator = RASimulator::new();
        let report_data = *blake3::hash(b"test-data").as_bytes();
        
        // Test quote generation
        let quote_result = simulator.get_quote(&report_data);
        assert!(quote_result.is_ok(), "Quote generation should succeed");
        
        let quote = quote_result.unwrap();
        assert!(!quote.quote_bytes.is_empty(), "Quote should have content");
        assert_eq!(quote.measurement.len(), 32, "Measurement should be 32 bytes");
        assert_eq!(quote.report_data[..32], report_data, "Report data should match");
        
        // Test quote verification
        let verify_result = simulator.verify_quote(&quote);
        assert!(verify_result.is_ok(), "Quote verification should succeed: {:?}", verify_result.err());
    }
    
    #[test]
    fn test_csv_output() {
        // Create test results
        let baseline_metrics = BaselineMetrics {
            dealer_dkg_ms: 100,
            pot_pin_verify_ms: 50,
            ceremony_wall_s: 2.5,
            operator_steps: 2,
            bytes_total_mb: 150.0,
            bytes_dkg_mb: 8.0,
            bytes_pot_mb: 142.0,
            audit_evidence_kb: 12.5,
            audit_sha256: "abc123".to_string(),
        };
        
        let result = EvaluationResult::Baseline {
            trial: 0,
            mode: EvaluationMode::Baseline,
            crs_mode: CrsMode::PublicPot,
            n: 16,
            t: 8,
            batch_size: 512,
            latency_ms: 0,
            rate_mbps: 0,
            metrics: baseline_metrics,
        };
        
        // Test CSV record conversion
        let csv_record = CsvRecord::from(&result);
        assert_eq!(csv_record.trial, 0);
        assert_eq!(csv_record.mode, "baseline");
        assert_eq!(csv_record.crs_mode, "public_pot");
        assert_eq!(csv_record.n, 16);
        assert_eq!(csv_record.dealer_dkg_ms, 100);
        assert_eq!(csv_record.pot_pin_verify_ms, 50);
    }
    
    #[test]
    fn test_simple_attested_setup() {
        // Test the simple attested setup implementation
        let mut rng = StdRng::seed_from_u64(42);
        let n = 4;
        let t = 2;
        let batch_size = 8;
        let share_domain: Vec<_> = (1..=n)
            .map(|i| <E as Pairing>::ScalarField::from(i as u64))
            .collect();
        
        let input = DealerInput {
            batch_size,
            n,
            t,
            share_domain,
            pot_id: Some("test-ceremony".to_string()),
        };
        
        let result = run_attested_setup_crypto_only::<E, _>(&mut rng, input);
        assert!(result.is_ok(), "Attested setup should succeed");
        
        let dealing = result.unwrap();
        assert_eq!(dealing.shares.len(), n);
        assert_eq!(dealing.commitments.share_commitments.len(), n);
        assert_eq!(dealing.transcript_digest.len(), 32);
        assert_eq!(dealing.meta.n, n);
        assert_eq!(dealing.meta.t, t);
    }
}
