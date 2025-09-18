pub mod dealer;
pub mod decryption;
pub mod encryption;
pub mod utils;
pub mod verification;

#[cfg(feature = "tee-ingress")]
pub mod envelope;                // from Subplan A
#[cfg(feature = "tee-ingress")]
pub mod attestation;             // from Subplan A

#[cfg(feature = "tee-dealer")]
pub mod attested_dealer;         // NEW
#[cfg(feature = "tee-dealer")]
pub mod dealer_consistency;      // NEW: public consistency checks for CRS/shares
#[cfg(feature = "tee-dealer")]
pub mod dealer_ra;               // NEW: dev RA verifier + policy
#[cfg(feature = "tee-dealer")]
pub mod dealer_transcript;       // NEW: transcript construction, digest

#[cfg(test)]
mod tests;