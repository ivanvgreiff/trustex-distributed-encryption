pub mod dealer;
pub mod decryption;
pub mod encryption;
pub mod utils;
pub mod verification;

#[cfg(feature = "tee-ingress")]
pub mod envelope;
#[cfg(feature = "tee-ingress")]
pub mod attestation;

#[cfg(feature = "attested-setup")]
pub mod attested_setup;

// Evaluation framework modules
pub mod evaluation {
    pub mod pot_handling;
    pub mod ra_simulation;
    pub mod metrics;
    pub mod simple_attested_setup;
}

#[cfg(test)]
mod tests;