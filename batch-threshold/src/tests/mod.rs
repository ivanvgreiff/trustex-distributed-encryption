#[cfg(test)]
pub mod attestation_tests;

#[cfg(all(test, feature = "tee-dealer", feature = "dev-attest"))]
pub mod attested_dealer_tests;