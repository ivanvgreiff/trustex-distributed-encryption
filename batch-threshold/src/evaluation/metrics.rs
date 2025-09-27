//! Metrics Collection and CSV Output Module
//!
//! Defines measurement structures and CSV serialization for evaluation results.
//! Supports both baseline (non-TEE) and attested (TEE) evaluation modes.

use serde::{Deserialize, Serialize};
use clap::ValueEnum;

#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum EvaluationMode {
    /// Baseline: trusted dealer + public PoT pin/verify
    Baseline,
    /// AttestedSetup: TEE-coordinated with extra crypto + RA
    Attested,
}

#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum CrsMode {
    /// Reuse and verify a known public PoT
    #[value(name = "public-pot")]
    PublicPot,
    /// Generate local CRS with same-τ verification
    #[value(name = "local-crs")]
    LocalCrs,
}

/// Baseline (non-TEE) ceremony metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineMetrics {
    /// DKG/trusted-dealer setup time (ms)
    pub dealer_dkg_ms: u64,
    /// PoT pin/verify time (ms)
    pub pot_pin_verify_ms: u64,
    /// End-to-end ceremony wall-clock time (s)
    pub ceremony_wall_s: f64,
    /// Number of operator actions required
    pub operator_steps: usize,
    /// Total bytes transferred (MB)
    pub bytes_total_mb: f64,
    /// DKG-specific bytes transferred (MB)
    pub bytes_dkg_mb: f64,
    /// PoT-specific bytes transferred (MB)
    pub bytes_pot_mb: f64,
    /// Audit evidence size (KB)
    pub audit_evidence_kb: f64,
    /// SHA256 hash of audit bundle
    pub audit_sha256: String,
}

/// AttestedSetup (TEE) ceremony metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestedMetrics {
    /// DKG/trusted-dealer setup time (ms) - same as baseline
    pub dealer_dkg_ms: u64,
    /// PoT pin/verify time (ms) - only when using public PoT
    pub pot_pin_verify_ms: u64,
    /// Share commitments computation time (ms)
    pub commitments_ms: u64,
    /// PK from commitments computation time (ms)
    pub pk_from_commitments_ms: u64,
    /// Transcript digest computation time (ms)
    pub transcript_digest_ms: u64,
    /// Same-τ verification time (ms) - only when using local CRS
    pub same_tau_verify_ms: u64,
    /// RA quote emission time (ms)
    pub ra_emit_ms: u64,
    /// RA quote verification time (ms)
    pub ra_verify_ms: u64,
    /// End-to-end ceremony wall-clock time (s)
    pub ceremony_wall_s: f64,
    /// Number of operator actions required
    pub operator_steps: usize,
    /// Time to publish audit bundle (s)
    pub attest_publish_s: f64,
    /// Total bytes transferred (MB)
    pub bytes_total_mb: f64,
    /// DKG-specific bytes transferred (MB)
    pub bytes_dkg_mb: f64,
    /// PoT-specific bytes transferred (MB)
    pub bytes_pot_mb: f64,
    /// Audit evidence size (KB)
    pub audit_evidence_kb: f64,
    /// SHA256 hash of audit bundle
    pub audit_sha256: String,
    /// TEE code measurement (hex)
    pub code_measurement: String,
}

/// Complete evaluation result for a single trial
#[derive(Debug, Clone)]
pub enum EvaluationResult {
    Baseline {
        trial: usize,
        mode: EvaluationMode,
        crs_mode: CrsMode,
        n: usize,
        t: usize,
        batch_size: usize,
        latency_ms: u64,
        rate_mbps: u64,
        metrics: BaselineMetrics,
    },
    Attested {
        trial: usize,
        mode: EvaluationMode,
        crs_mode: CrsMode,
        n: usize,
        t: usize,
        batch_size: usize,
        latency_ms: u64,
        rate_mbps: u64,
        metrics: AttestedMetrics,
    },
}

/// CSV record structure matching the specified schema
#[derive(Debug, Serialize)]
pub struct CsvRecord {
    pub trial: usize,
    pub mode: String,
    pub crs_mode: String,
    pub n: usize,
    pub t: usize,
    #[serde(rename = "B")]
    pub batch_size: usize,
    pub lat_ms: u64,
    pub rate_mbps: u64,
    pub dealer_dkg_ms: u64,
    pub pot_pin_verify_ms: u64,
    pub commitments_ms: u64,
    pub pk_from_commitments_ms: u64,
    pub transcript_digest_ms: u64,
    pub same_tau_verify_ms: u64,
    pub ra_emit_ms: u64,
    pub ra_verify_ms: u64,
    pub ceremony_wall_s: f64,
    pub operator_steps: usize,
    pub attest_publish_s: f64,
    pub bytes_total_mb: f64,
    pub bytes_dkg_mb: f64,
    pub bytes_pot_mb: f64,
    pub audit_evidence_kb: f64,
    pub audit_sha256: String,
    pub code_measurement: String,
}

impl From<&EvaluationResult> for CsvRecord {
    fn from(result: &EvaluationResult) -> Self {
        match result {
            EvaluationResult::Baseline {
                trial,
                mode,
                crs_mode,
                n,
                t,
                batch_size,
                latency_ms,
                rate_mbps,
                metrics,
            } => CsvRecord {
                trial: *trial,
                mode: format!("{:?}", mode).to_lowercase(),
                crs_mode: match crs_mode {
                    CrsMode::PublicPot => "public_pot".to_string(),
                    CrsMode::LocalCrs => "local_crs".to_string(),
                },
                n: *n,
                t: *t,
                batch_size: *batch_size,
                lat_ms: *latency_ms,
                rate_mbps: *rate_mbps,
                dealer_dkg_ms: metrics.dealer_dkg_ms,
                pot_pin_verify_ms: metrics.pot_pin_verify_ms,
                commitments_ms: 0, // N/A for baseline
                pk_from_commitments_ms: 0, // N/A for baseline
                transcript_digest_ms: 0, // N/A for baseline
                same_tau_verify_ms: 0, // N/A for baseline
                ra_emit_ms: 0, // N/A for baseline
                ra_verify_ms: 0, // N/A for baseline
                ceremony_wall_s: metrics.ceremony_wall_s,
                operator_steps: metrics.operator_steps,
                attest_publish_s: 0.0, // N/A for baseline
                bytes_total_mb: metrics.bytes_total_mb,
                bytes_dkg_mb: metrics.bytes_dkg_mb,
                bytes_pot_mb: metrics.bytes_pot_mb,
                audit_evidence_kb: metrics.audit_evidence_kb,
                audit_sha256: metrics.audit_sha256.clone(),
                code_measurement: String::new(), // N/A for baseline
            },
            EvaluationResult::Attested {
                trial,
                mode,
                crs_mode,
                n,
                t,
                batch_size,
                latency_ms,
                rate_mbps,
                metrics,
            } => CsvRecord {
                trial: *trial,
                mode: format!("{:?}", mode).to_lowercase(),
                crs_mode: match crs_mode {
                    CrsMode::PublicPot => "public_pot".to_string(),
                    CrsMode::LocalCrs => "local_crs".to_string(),
                },
                n: *n,
                t: *t,
                batch_size: *batch_size,
                lat_ms: *latency_ms,
                rate_mbps: *rate_mbps,
                dealer_dkg_ms: metrics.dealer_dkg_ms,
                pot_pin_verify_ms: metrics.pot_pin_verify_ms,
                commitments_ms: metrics.commitments_ms,
                pk_from_commitments_ms: metrics.pk_from_commitments_ms,
                transcript_digest_ms: metrics.transcript_digest_ms,
                same_tau_verify_ms: metrics.same_tau_verify_ms,
                ra_emit_ms: metrics.ra_emit_ms,
                ra_verify_ms: metrics.ra_verify_ms,
                ceremony_wall_s: metrics.ceremony_wall_s,
                operator_steps: metrics.operator_steps,
                attest_publish_s: metrics.attest_publish_s,
                bytes_total_mb: metrics.bytes_total_mb,
                bytes_dkg_mb: metrics.bytes_dkg_mb,
                bytes_pot_mb: metrics.bytes_pot_mb,
                audit_evidence_kb: metrics.audit_evidence_kb,
                audit_sha256: metrics.audit_sha256.clone(),
                code_measurement: metrics.code_measurement.clone(),
            },
        }
    }
}

impl EvaluationResult {
    /// Get the trial number
    pub fn trial(&self) -> usize {
        match self {
            EvaluationResult::Baseline { trial, .. } => *trial,
            EvaluationResult::Attested { trial, .. } => *trial,
        }
    }
    
    /// Get the evaluation mode
    pub fn mode(&self) -> &EvaluationMode {
        match self {
            EvaluationResult::Baseline { mode, .. } => mode,
            EvaluationResult::Attested { mode, .. } => mode,
        }
    }
    
    /// Get the CRS mode
    pub fn crs_mode(&self) -> &CrsMode {
        match self {
            EvaluationResult::Baseline { crs_mode, .. } => crs_mode,
            EvaluationResult::Attested { crs_mode, .. } => crs_mode,
        }
    }
    
    /// Get the ceremony wall-clock time
    pub fn ceremony_wall_s(&self) -> f64 {
        match self {
            EvaluationResult::Baseline { metrics, .. } => metrics.ceremony_wall_s,
            EvaluationResult::Attested { metrics, .. } => metrics.ceremony_wall_s,
        }
    }
    
    /// Get the number of operator steps
    pub fn operator_steps(&self) -> usize {
        match self {
            EvaluationResult::Baseline { metrics, .. } => metrics.operator_steps,
            EvaluationResult::Attested { metrics, .. } => metrics.operator_steps,
        }
    }
    
    /// Get total bytes transferred
    pub fn bytes_total_mb(&self) -> f64 {
        match self {
            EvaluationResult::Baseline { metrics, .. } => metrics.bytes_total_mb,
            EvaluationResult::Attested { metrics, .. } => metrics.bytes_total_mb,
        }
    }
    
    /// Get audit evidence size
    pub fn audit_evidence_kb(&self) -> f64 {
        match self {
            EvaluationResult::Baseline { metrics, .. } => metrics.audit_evidence_kb,
            EvaluationResult::Attested { metrics, .. } => metrics.audit_evidence_kb,
        }
    }
    
    /// Calculate total crypto time (sum of all crypto operations)
    pub fn total_crypto_ms(&self) -> u64 {
        match self {
            EvaluationResult::Baseline { metrics, .. } => {
                metrics.dealer_dkg_ms + metrics.pot_pin_verify_ms
            },
            EvaluationResult::Attested { metrics, .. } => {
                metrics.dealer_dkg_ms + 
                metrics.pot_pin_verify_ms + 
                metrics.commitments_ms +
                metrics.pk_from_commitments_ms +
                metrics.transcript_digest_ms +
                metrics.same_tau_verify_ms +
                metrics.ra_emit_ms +
                metrics.ra_verify_ms
            },
        }
    }
    
    /// Calculate the overhead of attested vs baseline (only valid for attested results)
    pub fn calculate_overhead(&self, baseline: &EvaluationResult) -> Option<OverheadAnalysis> {
        match (self, baseline) {
            (EvaluationResult::Attested { metrics: att, .. }, 
             EvaluationResult::Baseline { metrics: base, .. }) => {
                Some(OverheadAnalysis {
                    crypto_overhead_ms: self.total_crypto_ms() as i64 - baseline.total_crypto_ms() as i64,
                    crypto_overhead_pct: ((self.total_crypto_ms() as f64 / baseline.total_crypto_ms() as f64) - 1.0) * 100.0,
                    wall_clock_overhead_s: att.ceremony_wall_s - base.ceremony_wall_s,
                    wall_clock_overhead_pct: ((att.ceremony_wall_s / base.ceremony_wall_s) - 1.0) * 100.0,
                    operator_steps_delta: att.operator_steps as i32 - base.operator_steps as i32,
                    bytes_overhead_mb: att.bytes_total_mb - base.bytes_total_mb,
                    audit_size_overhead_kb: att.audit_evidence_kb - base.audit_evidence_kb,
                })
            },
            _ => None,
        }
    }
}

/// Overhead analysis comparing attested vs baseline
#[derive(Debug, Clone)]
pub struct OverheadAnalysis {
    pub crypto_overhead_ms: i64,
    pub crypto_overhead_pct: f64,
    pub wall_clock_overhead_s: f64,
    pub wall_clock_overhead_pct: f64,
    pub operator_steps_delta: i32,
    pub bytes_overhead_mb: f64,
    pub audit_size_overhead_kb: f64,
}

/// Summary statistics for a collection of results
#[derive(Debug)]
pub struct SummaryStats {
    pub count: usize,
    pub mean: f64,
    pub median: f64,
    pub std_dev: f64,
    pub min: f64,
    pub max: f64,
}

impl SummaryStats {
    /// Calculate summary statistics for a collection of values
    pub fn calculate(values: &[f64]) -> Self {
        if values.is_empty() {
            return Self {
                count: 0,
                mean: 0.0,
                median: 0.0,
                std_dev: 0.0,
                min: 0.0,
                max: 0.0,
            };
        }
        
        let count = values.len();
        let mean = values.iter().sum::<f64>() / count as f64;
        
        let mut sorted = values.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        
        let median = if count % 2 == 0 {
            (sorted[count / 2 - 1] + sorted[count / 2]) / 2.0
        } else {
            sorted[count / 2]
        };
        
        let variance = values.iter()
            .map(|x| (x - mean).powi(2))
            .sum::<f64>() / count as f64;
        let std_dev = variance.sqrt();
        
        let min = *sorted.first().unwrap();
        let max = *sorted.last().unwrap();
        
        Self { count, mean, median, std_dev, min, max }
    }
}

/// Aggregate analysis across multiple trials
#[derive(Debug)]
pub struct AggregateAnalysis {
    pub crypto_time_stats: SummaryStats,
    pub wall_clock_stats: SummaryStats,
    pub operator_steps_stats: SummaryStats,
    pub bytes_total_stats: SummaryStats,
    pub audit_size_stats: SummaryStats,
}

impl AggregateAnalysis {
    /// Calculate aggregate analysis for a collection of results
    pub fn calculate(results: &[EvaluationResult]) -> Self {
        let crypto_times: Vec<f64> = results.iter()
            .map(|r| r.total_crypto_ms() as f64)
            .collect();
            
        let wall_clocks: Vec<f64> = results.iter()
            .map(|r| r.ceremony_wall_s())
            .collect();
            
        let operator_steps: Vec<f64> = results.iter()
            .map(|r| r.operator_steps() as f64)
            .collect();
            
        let bytes_totals: Vec<f64> = results.iter()
            .map(|r| r.bytes_total_mb())
            .collect();
            
        let audit_sizes: Vec<f64> = results.iter()
            .map(|r| r.audit_evidence_kb())
            .collect();
        
        Self {
            crypto_time_stats: SummaryStats::calculate(&crypto_times),
            wall_clock_stats: SummaryStats::calculate(&wall_clocks),
            operator_steps_stats: SummaryStats::calculate(&operator_steps),
            bytes_total_stats: SummaryStats::calculate(&bytes_totals),
            audit_size_stats: SummaryStats::calculate(&audit_sizes),
        }
    }
}

/// Utility functions for metrics analysis

/// Calculate percentile for a sorted array
pub fn percentile(sorted_values: &[f64], p: f64) -> f64 {
    if sorted_values.is_empty() {
        return 0.0;
    }
    
    let index = (p / 100.0) * (sorted_values.len() - 1) as f64;
    let lower = index.floor() as usize;
    let upper = index.ceil() as usize;
    
    if lower == upper {
        sorted_values[lower]
    } else {
        let weight = index - lower as f64;
        sorted_values[lower] * (1.0 - weight) + sorted_values[upper] * weight
    }
}

/// Format duration in human-readable form
pub fn format_duration_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        let minutes = ms / 60_000;
        let seconds = (ms % 60_000) as f64 / 1000.0;
        format!("{}m {:.1}s", minutes, seconds)
    }
}

/// Format bytes in human-readable form
pub fn format_bytes(bytes: f64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB"];
    let mut size = bytes;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{:.0}{}", size, UNITS[unit_index])
    } else {
        format!("{:.2}{}", size, UNITS[unit_index])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_baseline_metrics() -> BaselineMetrics {
        BaselineMetrics {
            dealer_dkg_ms: 100,
            pot_pin_verify_ms: 50,
            ceremony_wall_s: 5.0,
            operator_steps: 2,
            bytes_total_mb: 150.0,
            bytes_dkg_mb: 8.0,
            bytes_pot_mb: 142.0,
            audit_evidence_kb: 12.5,
            audit_sha256: "abc123".to_string(),
        }
    }
    
    fn create_attested_metrics() -> AttestedMetrics {
        AttestedMetrics {
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
        }
    }
    
    #[test]
    fn test_csv_record_conversion_baseline() {
        let result = EvaluationResult::Baseline {
            trial: 0,
            mode: EvaluationMode::Baseline,
            crs_mode: CrsMode::PublicPot,
            n: 16,
            t: 8,
            batch_size: 512,
            latency_ms: 0,
            rate_mbps: 0,
            metrics: create_baseline_metrics(),
        };
        
        let record = CsvRecord::from(&result);
        assert_eq!(record.trial, 0);
        assert_eq!(record.mode, "baseline");
        assert_eq!(record.crs_mode, "public_pot");
        assert_eq!(record.n, 16);
        assert_eq!(record.t, 8);
        assert_eq!(record.batch_size, 512);
        assert_eq!(record.dealer_dkg_ms, 100);
        assert_eq!(record.pot_pin_verify_ms, 50);
        assert_eq!(record.commitments_ms, 0); // N/A for baseline
        assert_eq!(record.ra_emit_ms, 0); // N/A for baseline
    }
    
    #[test]
    fn test_csv_record_conversion_attested() {
        let result = EvaluationResult::Attested {
            trial: 1,
            mode: EvaluationMode::Attested,
            crs_mode: CrsMode::LocalCrs,
            n: 64,
            t: 32,
            batch_size: 512,
            latency_ms: 10,
            rate_mbps: 100,
            metrics: create_attested_metrics(),
        };
        
        let record = CsvRecord::from(&result);
        assert_eq!(record.trial, 1);
        assert_eq!(record.mode, "attested");
        assert_eq!(record.crs_mode, "local_crs");
        assert_eq!(record.n, 64);
        assert_eq!(record.t, 32);
        assert_eq!(record.commitments_ms, 25);
        assert_eq!(record.ra_emit_ms, 25);
        assert_eq!(record.code_measurement, "789abc");
    }
    
    #[test]
    fn test_total_crypto_time_calculation() {
        let baseline_result = EvaluationResult::Baseline {
            trial: 0,
            mode: EvaluationMode::Baseline,
            crs_mode: CrsMode::PublicPot,
            n: 16,
            t: 8,
            batch_size: 512,
            latency_ms: 0,
            rate_mbps: 0,
            metrics: create_baseline_metrics(),
        };
        
        let attested_result = EvaluationResult::Attested {
            trial: 0,
            mode: EvaluationMode::Attested,
            crs_mode: CrsMode::PublicPot,
            n: 16,
            t: 8,
            batch_size: 512,
            latency_ms: 0,
            rate_mbps: 0,
            metrics: create_attested_metrics(),
        };
        
        assert_eq!(baseline_result.total_crypto_ms(), 150); // 100 + 50
        assert_eq!(attested_result.total_crypto_ms(), 235); // 100 + 50 + 25 + 15 + 5 + 0 + 25 + 15
    }
    
    #[test]
    fn test_overhead_analysis() {
        let baseline_result = EvaluationResult::Baseline {
            trial: 0,
            mode: EvaluationMode::Baseline,
            crs_mode: CrsMode::PublicPot,
            n: 16,
            t: 8,
            batch_size: 512,
            latency_ms: 0,
            rate_mbps: 0,
            metrics: create_baseline_metrics(),
        };
        
        let attested_result = EvaluationResult::Attested {
            trial: 0,
            mode: EvaluationMode::Attested,
            crs_mode: CrsMode::PublicPot,
            n: 16,
            t: 8,
            batch_size: 512,
            latency_ms: 0,
            rate_mbps: 0,
            metrics: create_attested_metrics(),
        };
        
        let overhead = attested_result.calculate_overhead(&baseline_result).unwrap();
        
        assert_eq!(overhead.crypto_overhead_ms, 85); // 235 - 150
        assert!(overhead.crypto_overhead_pct > 50.0); // Should be ~56.7%
        assert!(overhead.wall_clock_overhead_s < 0.0); // Attested is faster wall-clock
        assert_eq!(overhead.operator_steps_delta, 0); // Same number of steps
    }
    
    #[test]
    fn test_summary_stats() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let stats = SummaryStats::calculate(&values);
        
        assert_eq!(stats.count, 5);
        assert_eq!(stats.mean, 3.0);
        assert_eq!(stats.median, 3.0);
        assert_eq!(stats.min, 1.0);
        assert_eq!(stats.max, 5.0);
        assert!(stats.std_dev > 0.0);
    }
    
    #[test]
    fn test_percentile_calculation() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        
        assert_eq!(percentile(&values, 0.0), 1.0);
        assert_eq!(percentile(&values, 50.0), 3.0);
        assert_eq!(percentile(&values, 100.0), 5.0);
    }
    
    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration_ms(500), "500ms");
        assert_eq!(format_duration_ms(1500), "1.5s");
        assert_eq!(format_duration_ms(65000), "1m 5.0s");
    }
    
    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512.0), "512B");
        assert_eq!(format_bytes(1536.0), "1.50KB");
        assert_eq!(format_bytes(1048576.0), "1.00MB");
    }
}
