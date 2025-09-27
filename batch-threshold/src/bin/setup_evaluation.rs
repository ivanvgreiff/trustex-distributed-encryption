//! Setup Evaluation Framework Binary
//! 
//! Comprehensive evaluation comparing baseline (non-TEE) vs AttestedSetup (TEE-coordinated)
//! one-time ceremony protocols. Measures crypto microbench and operational wall-clock separately.

use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::path::PathBuf;
use std::fs;

use ark_bls12_381::Bls12_381 as E;
use ark_ec::pairing::Pairing;
use rand::rngs::StdRng;
use rand::SeedableRng;
use clap::Parser;

use batch_threshold::dealer::Dealer;

// Import our test modules (we'll need to make them public)
use batch_threshold::evaluation::{
    pot_handling::{PotHandler, PotMode},
    ra_simulation::{RASimulator, MockQuote},
    metrics::{BaselineMetrics, AttestedMetrics, EvaluationResult, CsvRecord, EvaluationMode, CrsMode},
    simple_attested_setup::{run_attested_setup_crypto_only, DealerInput, AttestedDealing},
};

/// Global operator step counter for wall-clock measurements
static OP_STEPS: AtomicUsize = AtomicUsize::new(0);

#[derive(Parser, Debug)]
#[command(name = "setup-evaluation")]
#[command(about = "Evaluate baseline vs AttestedSetup ceremony protocols")]
pub struct Args {
    /// Evaluation mode: baseline (non-TEE) or attested (TEE-coordinated)
    #[arg(long, value_enum)]
    pub mode: EvaluationMode,
    
    /// CRS handling mode
    #[arg(long, value_enum, default_value = "public-pot")]
    pub crs_mode: CrsMode,
    
    /// PoT source (path or URL) when using public-pot mode
    #[arg(long, default_value = "eth-kzg-ceremony")]
    pub pot_url: String,
    
    /// Number of parties
    #[arg(long, default_value = "16")]
    pub n: usize,
    
    /// Threshold (t+1 parties needed)
    #[arg(long)]
    pub t: Option<usize>,
    
    /// Batch size
    #[arg(long, default_value = "512")]
    pub batch_size: usize,
    
    /// Network latency simulation (ms)
    #[arg(long, default_value = "0")]
    pub latency_ms: u64,
    
    /// Network jitter simulation (ms)
    #[arg(long, default_value = "0")]
    pub jitter_ms: u64,
    
    /// Network rate limit simulation (Mbps, 0 = unlimited)
    #[arg(long, default_value = "0")]
    pub rate_mbps: u64,
    
    /// Number of trials to run
    #[arg(long, default_value = "5")]
    pub trials: usize,
    
    /// Output directory for results
    #[arg(long, default_value = "./results")]
    pub out: PathBuf,
}

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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Validate arguments
    let t = args.t.unwrap_or(args.n / 2);
    if t >= args.n {
        return Err("Threshold t must be < n".into());
    }
    
    // Create output directory
    fs::create_dir_all(&args.out)?;
    
    // Initialize components
    let pot_handler = PotHandler::new(match args.crs_mode {
        CrsMode::PublicPot => PotMode::PublicPot(args.pot_url.clone()),
        CrsMode::LocalCrs => PotMode::LocalCrs,
    });
    
    let ra_sim = RASimulator::new();
    let net_sim = NetworkSim::new(args.latency_ms, args.jitter_ms, args.rate_mbps);
    
    println!("🔬 Setup Evaluation Framework");
    println!("Mode: {:?}, CRS: {:?}", args.mode, args.crs_mode);
    println!("Parameters: n={}, t={}, B={}", args.n, t, args.batch_size);
    println!("Trials: {}, Output: {:?}", args.trials, args.out);
    println!();
    
    // Run evaluation trials
    let mut results = Vec::new();
    
    for trial in 0..args.trials {
        println!("🔄 Trial {}/{}", trial + 1, args.trials);
        
        let result = match args.mode {
            EvaluationMode::Baseline => {
                run_baseline_trial(trial, &args, t, &pot_handler, &net_sim)?
            }
            EvaluationMode::Attested => {
                run_attested_trial(trial, &args, t, &pot_handler, &ra_sim, &net_sim)?
            }
        };
        
        results.push(result);
        println!("✅ Trial {} completed", trial + 1);
    }
    
    // Write CSV results
    let csv_path = args.out.join("setup_evaluation_results.csv");
    write_csv_results(&csv_path, &results)?;
    
    // Print summary
    print_summary(&results);
    
    println!("\n📊 Results written to: {:?}", csv_path);
    Ok(())
}

/// Run a single baseline (non-TEE) trial
fn run_baseline_trial(
    trial: usize,
    args: &Args,
    t: usize,
    pot_handler: &PotHandler,
    net_sim: &NetworkSim,
) -> Result<EvaluationResult, Box<dyn std::error::Error>> {
    let mut bytes_counter = ByteCounter::default();
    let ceremony_start = Instant::now();
    OP_STEPS.store(0, Relaxed);
    
    // Step 1: Provision (operator action)
    OP_STEPS.fetch_add(1, Relaxed); // "Initialize ceremony"
    net_sim.apply_delay();
    
    // Step 2: DKG / trusted-dealer setup
    let mut rng = StdRng::seed_from_u64(42 + trial as u64);
    
    let dealer_dkg_start = Instant::now();
    let mut dealer = Dealer::<E>::new_with_rng(args.batch_size, args.n, t, &mut rng);
    let (crs, shares) = dealer.setup(&mut rng);
    let pk = dealer.get_pk();
    let dealer_dkg_ms = dealer_dkg_start.elapsed().as_millis() as u64;
    
    // Simulate DKG network traffic (shares distribution)
    let share_bytes = args.n * 32; // Approximate bytes per share
    bytes_counter.add_dkg(share_bytes);
    
    // Step 3: PoT pin/verify
    let pot_start = Instant::now();
    let pot_result = pot_handler.fetch_and_verify(&args.pot_url)?;
    let pot_pin_verify_ms = pot_start.elapsed().as_millis() as u64;
    bytes_counter.add_pot(pot_result.bytes_fetched);
    
    // Step 4: Finalize ceremony (operator action)
    OP_STEPS.fetch_add(1, Relaxed); // "Finalize and publish"
    
    let ceremony_wall_s = ceremony_start.elapsed().as_secs_f64();
    let operator_steps = OP_STEPS.load(Relaxed);
    
    // Manual audit bundle (no RA)
    let audit_evidence_kb = estimate_baseline_audit_size(&crs, &shares, &pk);
    
    let metrics = BaselineMetrics {
        dealer_dkg_ms,
        pot_pin_verify_ms,
        ceremony_wall_s,
        operator_steps,
        bytes_total_mb: bytes_counter.total_mb(),
        bytes_dkg_mb: bytes_counter.dkg_total_mb(),
        bytes_pot_mb: bytes_counter.pot_total_mb(),
        audit_evidence_kb,
        audit_sha256: hex::encode(blake3::hash(b"baseline-audit-bundle").as_bytes()),
    };
    
    Ok(EvaluationResult::Baseline {
        trial,
        mode: EvaluationMode::Baseline,
        crs_mode: args.crs_mode.clone(),
        n: args.n,
        t,
        batch_size: args.batch_size,
        latency_ms: args.latency_ms,
        rate_mbps: args.rate_mbps,
        metrics,
    })
}

/// Run a single attested (TEE) trial  
fn run_attested_trial(
    trial: usize,
    args: &Args,
    t: usize,
    pot_handler: &PotHandler,
    ra_sim: &RASimulator,
    net_sim: &NetworkSim,
) -> Result<EvaluationResult, Box<dyn std::error::Error>> {
    let mut bytes_counter = ByteCounter::default();
    let ceremony_start = Instant::now();
    OP_STEPS.store(0, Relaxed);
    
    // Step 0: Provision enclave (operator action)
    OP_STEPS.fetch_add(1, Relaxed); // "Provision TEE and allowlist"
    net_sim.apply_delay();
    
    // Step 1: Same DKG as baseline (but coordinated by TEE)
    let mut rng = StdRng::seed_from_u64(42 + trial as u64);
    let share_domain: Vec<_> = (1..=args.n)
        .map(|i| <E as Pairing>::ScalarField::from(i as u64))
        .collect();
    
    let input = DealerInput {
        batch_size: args.batch_size,
        n: args.n,
        t,
        share_domain: share_domain.clone(),
        pot_id: Some(args.pot_url.clone()),
    };
    
    let dealer_dkg_start = Instant::now();
    let dealing = run_attested_setup_crypto_only::<E, _>(&mut rng, input)?;
    let dealer_dkg_ms = dealer_dkg_start.elapsed().as_millis() as u64;
    
    // Simulate DKG network traffic
    let share_bytes = args.n * 32;
    bytes_counter.add_dkg(share_bytes);
    
    // Step 2: Extract individual crypto operation timings from the dealing
    let commitments_ms = dealing.commitments_ms;
    let pk_from_commitments_ms = dealing.pk_from_commitments_ms;
    let transcript_digest_ms = dealing.transcript_digest_ms;
    
    // Step 3: CRS/PoT handling based on mode
    let (pot_pin_verify_ms, same_tau_verify_ms) = match args.crs_mode {
        CrsMode::PublicPot => {
            let pot_start = Instant::now();
            let pot_result = pot_handler.fetch_and_verify(&args.pot_url)?;
            let pot_ms = pot_start.elapsed().as_millis() as u64;
            bytes_counter.add_pot(pot_result.bytes_fetched);
            (pot_ms, 0)
        }
        CrsMode::LocalCrs => {
            let same_tau_start = Instant::now();
            pot_handler.verify_same_tau(&dealing.crs)?;
            let same_tau_ms = same_tau_start.elapsed().as_millis() as u64;
            (0, same_tau_ms)
        }
    };
    
    // Step 4: Remote Attestation
    let ra_emit_start = Instant::now();
    let quote = ra_sim.get_quote(&dealing.transcript_digest)?;
    let ra_emit_ms = ra_emit_start.elapsed().as_millis() as u64;
    
    let ra_verify_start = Instant::now();
    ra_sim.verify_quote(&quote)?;
    let ra_verify_ms = ra_verify_start.elapsed().as_millis() as u64;
    
    // Step 5: Audit bundle creation
    let audit_start = Instant::now();
    let audit_evidence_kb = create_audit_bundle(&dealing, &quote);
    let attest_publish_s = audit_start.elapsed().as_secs_f64();
    
    // Step 6: Finalize ceremony (operator action)  
    OP_STEPS.fetch_add(1, Relaxed); // "Publish audit bundle"
    
    let ceremony_wall_s = ceremony_start.elapsed().as_secs_f64();
    let operator_steps = OP_STEPS.load(Relaxed);
    
    let metrics = AttestedMetrics {
        dealer_dkg_ms,
        pot_pin_verify_ms,
        commitments_ms,
        pk_from_commitments_ms,
        transcript_digest_ms,
        same_tau_verify_ms,
        ra_emit_ms,
        ra_verify_ms,
        ceremony_wall_s,
        operator_steps,
        attest_publish_s,
        bytes_total_mb: bytes_counter.total_mb(),
        bytes_dkg_mb: bytes_counter.dkg_total_mb(),
        bytes_pot_mb: bytes_counter.pot_total_mb(),
        audit_evidence_kb,
        audit_sha256: hex::encode(blake3::hash(&quote.quote_bytes).as_bytes()),
        code_measurement: hex::encode(quote.measurement),
    };
    
    Ok(EvaluationResult::Attested {
        trial,
        mode: EvaluationMode::Attested,
        crs_mode: args.crs_mode.clone(),
        n: args.n,
        t,
        batch_size: args.batch_size,
        latency_ms: args.latency_ms,
        rate_mbps: args.rate_mbps,
        metrics,
    })
}

/// Estimate baseline audit bundle size (no RA)
fn estimate_baseline_audit_size(
    crs: &batch_threshold::dealer::CRS<E>,
    shares: &[<E as Pairing>::ScalarField],
    _pk: &<E as Pairing>::G2,
) -> f64 {
    // Approximate serialized sizes
    let crs_size = crs.powers_of_g.len() * 48; // G1 compressed
    let htau_size = 96; // G2 compressed
    let pk_size = 96; // G2 compressed
    let shares_size = shares.len() * 32; // ScalarField
    
    let total_bytes = crs_size + htau_size + pk_size + shares_size + 64; // metadata
    total_bytes as f64 / 1024.0 // KB
}

/// Create audit bundle for attested setup
fn create_audit_bundle(dealing: &AttestedDealing<E>, quote: &MockQuote) -> f64 {
    // Approximate serialized sizes
    let transcript_hash_size = 32;
    let pk_size = 96; // G2 compressed  
    let commitments_size = dealing.commitments.share_commitments.len() * 96; // G2 compressed
    let pot_id_size = dealing.meta.pot_id.as_ref().map_or(0, |s| s.len());
    let quote_size = quote.quote_bytes.len();
    let measurement_size = 32;
    
    let total_bytes = transcript_hash_size + pk_size + commitments_size + 
                     pot_id_size + quote_size + measurement_size + 128; // metadata
    total_bytes as f64 / 1024.0 // KB
}

/// Write results to CSV file
fn write_csv_results(
    path: &PathBuf, 
    results: &[EvaluationResult]
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::Writer::from_path(path)?;
    
    // Write header
    wtr.write_record(&[
        "trial", "mode", "crs_mode", "n", "t", "B", "lat_ms", "rate_mbps",
        "dealer_dkg_ms", "pot_pin_verify_ms", "commitments_ms", "pk_from_commitments_ms",
        "transcript_digest_ms", "same_tau_verify_ms", "ra_emit_ms", "ra_verify_ms",
        "ceremony_wall_s", "operator_steps", "attest_publish_s",
        "bytes_total_mb", "bytes_dkg_mb", "bytes_pot_mb", "audit_evidence_kb",
        "audit_sha256", "code_measurement"
    ])?;
    
    // Write data rows
    for result in results {
        let record = CsvRecord::from(result);
        wtr.serialize(record)?;
    }
    
    wtr.flush()?;
    Ok(())
}

/// Print summary statistics
fn print_summary(results: &[EvaluationResult]) {
    if results.is_empty() {
        return;
    }
    
    println!("\n📈 Summary Statistics");
    println!("====================");
    
    match &results[0] {
        EvaluationResult::Baseline { .. } => {
            let metrics: Vec<_> = results.iter().filter_map(|r| {
                if let EvaluationResult::Baseline { metrics, .. } = r {
                    Some(metrics)
                } else {
                    None
                }
            }).collect();
            
            if !metrics.is_empty() {
                let avg_dkg = metrics.iter().map(|m| m.dealer_dkg_ms).sum::<u64>() as f64 / metrics.len() as f64;
                let avg_pot = metrics.iter().map(|m| m.pot_pin_verify_ms).sum::<u64>() as f64 / metrics.len() as f64;
                let avg_wall = metrics.iter().map(|m| m.ceremony_wall_s).sum::<f64>() / metrics.len() as f64;
                let avg_steps = metrics.iter().map(|m| m.operator_steps).sum::<usize>() as f64 / metrics.len() as f64;
                let avg_bytes_total = metrics.iter().map(|m| m.bytes_total_mb).sum::<f64>() / metrics.len() as f64;
                let avg_audit_kb = metrics.iter().map(|m| m.audit_evidence_kb).sum::<f64>() / metrics.len() as f64;
                
                println!("Baseline (non-TEE) - {} trials:", metrics.len());
                println!("  DKG setup: {:.1} ms", avg_dkg);
                println!("  PoT verify: {:.1} ms", avg_pot);
                println!("  Wall-clock: {:.2} s", avg_wall);
                println!("  Operator steps: {:.1}", avg_steps);
                println!("  Total bytes: {:.2} MB", avg_bytes_total);
                println!("  Audit evidence: {:.1} KB", avg_audit_kb);
            }
        }
        EvaluationResult::Attested { .. } => {
            let metrics: Vec<_> = results.iter().filter_map(|r| {
                if let EvaluationResult::Attested { metrics, .. } = r {
                    Some(metrics)
                } else {
                    None
                }
            }).collect();
            
            if !metrics.is_empty() {
                let avg_dkg = metrics.iter().map(|m| m.dealer_dkg_ms).sum::<u64>() as f64 / metrics.len() as f64;
                let avg_commitments = metrics.iter().map(|m| m.commitments_ms).sum::<u64>() as f64 / metrics.len() as f64;
                let avg_pk = metrics.iter().map(|m| m.pk_from_commitments_ms).sum::<u64>() as f64 / metrics.len() as f64;
                let avg_digest = metrics.iter().map(|m| m.transcript_digest_ms).sum::<u64>() as f64 / metrics.len() as f64;
                let avg_pot = metrics.iter().map(|m| m.pot_pin_verify_ms).sum::<u64>() as f64 / metrics.len() as f64;
                let avg_same_tau = metrics.iter().map(|m| m.same_tau_verify_ms).sum::<u64>() as f64 / metrics.len() as f64;
                let avg_ra_emit = metrics.iter().map(|m| m.ra_emit_ms).sum::<u64>() as f64 / metrics.len() as f64;
                let avg_ra_verify = metrics.iter().map(|m| m.ra_verify_ms).sum::<u64>() as f64 / metrics.len() as f64;
                let avg_wall = metrics.iter().map(|m| m.ceremony_wall_s).sum::<f64>() / metrics.len() as f64;
                let avg_steps = metrics.iter().map(|m| m.operator_steps).sum::<usize>() as f64 / metrics.len() as f64;
                let avg_bytes_total = metrics.iter().map(|m| m.bytes_total_mb).sum::<f64>() / metrics.len() as f64;
                let avg_audit_kb = metrics.iter().map(|m| m.audit_evidence_kb).sum::<f64>() / metrics.len() as f64;
                
                println!("AttestedSetup (TEE) - {} trials:", metrics.len());
                println!("  DKG setup: {:.1} ms", avg_dkg);
                println!("  Share commitments: {:.1} ms", avg_commitments);
                println!("  PK from commitments: {:.1} ms", avg_pk);
                println!("  Transcript digest: {:.1} ms", avg_digest);
                if avg_pot > 0.0 {
                    println!("  PoT verify: {:.1} ms", avg_pot);
                }
                if avg_same_tau > 0.0 {
                    println!("  Same-τ verify: {:.1} ms", avg_same_tau);
                }
                println!("  RA emit: {:.1} ms", avg_ra_emit);
                println!("  RA verify: {:.1} ms", avg_ra_verify);
                println!("  Wall-clock: {:.2} s", avg_wall);
                println!("  Operator steps: {:.1}", avg_steps);
                println!("  Total bytes: {:.2} MB", avg_bytes_total);
                println!("  Audit evidence: {:.1} KB", avg_audit_kb);
            }
        }
    }
}
