# Batched Threshold Encryption++
Rust implementation of the improved batched-threshold encryption scheme introduced in [ePrint:2024/1516](https://eprint.iacr.org/2024/1516).
For virtually all applications, this implementation should be preferred over the [original scheme](https://github.com/guruvamsi-policharla/batched-threshold-encryption) as it does not suffer from a per epoch setup and has a much simpler initial setup.
See the [paper](https://eprint.iacr.org/2024/1516) for a detailed comparison.

Use ```cargo bench``` to benchmark `encrypt`, `partial_decrypt` and `decrypt_all`.

Use ```cargo run --example endtoend``` to check correctness of the implementation.

Use ```cargo run --example attested_setup_demo --features attested-setup``` to see AttestedSetup in crypto-only mode.

Use ```cargo run --example attested_setup_demo --features attested-setup,dev-attested-setup``` to see AttestedSetup with dev signatures.

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Dependencies
* [arkworks](http://arkworks.rs) project for finite field and elliptic curve arithmetic.
* [merlin](https://github.com/dalek-cryptography/merlin) library for implementing the Fiat-Shamir transform.

## Overview
* [`src/dealer`](src/dealer.rs): Contains an implementation of the `setup` methods executed by a trusted dealer for the batched threshold encryption scheme.
* [`src/encryption`](src/encryption.rs): Contains an implementation of the `encrypt` method for the batched threshold encryption scheme.
* [`src/decryption`](src/decryption.rs): Contains an implementation of:
  * `partial_decrypt` - computes the message sent by each member of the committee.
  * `decrypt_all` - gathers partial decryptions and recovers all messages from the batch of ciphertexts. This uses [FK20](https://github.com/khovratovich/Kate/blob/master/Kate_amortized.pdf) to compute all KZG opening proofs in quasi-linear time.
* [`src/attested_setup`](src/attested_setup.rs): **Subplan B (AttestedSetup)** - Implements one-time DKG/PoT coordination with audit scaffolding. No real TEE - provides dev-mode simulation with public verification checks.

## AttestedSetup (Dev Mode)

The `attested_setup` module implements **Subplan B** from the HbTPKE-TEE design, providing:

### Key Features
- **One-time setup coordination**: Coordinates the one-time DKG and Powers-of-Tau ceremony
- **Public verification**: Implements CRS same-τ checks and pk-from-commitments verification
- **Transcript generation**: Creates canonical transcript digests for audit logging
- **Dev attestation**: Optional Ed25519 signatures over transcript digests (no real TEE required)
- **Policy enforcement**: Configurable verification policies for measurement allowlists and timestamp validation

### Artifacts Produced
The transcript covers and binds exactly the one-time setup artifacts from the base protocol:
- **CRS**: Powers-of-τ ceremony output `{g, g^τ, ..., g^{τ^{B-1}}; h, h^τ}`
- **Public key**: `pk = h^sk` 
- **Share commitments**: `{h^[sk]_j}` for each party j
- **Metadata**: Setup parameters (n, t, batch_size, share_domain, pot_id)

### Usage Modes

**Crypto-only mode** (no signatures):
```rust
let dealing = run_attested_setup_crypto_only::<E, _>(&mut rng, input)?;
```

**Dev mode** (with Ed25519 signatures):
```rust 
let dev_sk = SigningKey::generate(&mut rng);
let dealing = run_attested_setup_dev::<E, _>(&mut rng, input, &dev_sk)?;
```

**Verification** (with policy):
```rust
let policy = DealerPolicy {
    dev_mode: true,
    max_skew_ms: 60_000,
    allowlisted_measurements: vec![blake3::hash(b"attested-setup-dev@v1").into()],
    dev_verifying_key: Some(verifying_key),
};
verify_attested_dealing::<E>(&dealing, &policy)?;
```

### What This Provides
- **Auditable setup**: All setup artifacts are bound in a canonical transcript with cryptographic digest
- **Public verification**: CRS consistency and commitment correctness can be verified by any party
- **No additional trust**: Relies only on the same assumptions as the base threshold encryption scheme
- **TEE-ready interface**: When hardware is available, real attestation can replace dev signatures without changing the API

### What This Doesn't Change
- **Decryption performance**: The dominant cost remains sigma-style proof verification during batch decryption (≈99% of partial-decrypt time per the paper)
- **Per-epoch operations**: No per-epoch setup is required - this is a one-time coordination step
- **Core cryptography**: The underlying threshold encryption scheme is unchanged

## License
This library is released under the MIT License.
