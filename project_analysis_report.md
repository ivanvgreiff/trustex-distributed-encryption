# Batched Threshold Encryption++ Project Analysis

## Project Overview

**Project Name:** `batch-threshold`  
**Version:** 0.1.0  
**Author:** Guru-Vamsi Policharla  
**Language:** Rust (Edition 2021)  
**License:** MIT  

This is a Rust implementation of the improved batched-threshold encryption scheme from [ePrint:2024/1516](https://eprint.iacr.org/2024/1516). The project implements a cryptographic protocol that allows multiple parties to collaboratively decrypt batches of ciphertexts using threshold cryptography.

### Key Features
- **Batched Operations**: Encrypt/decrypt multiple messages efficiently in batches
- **Threshold Cryptography**: Requires `t+1` parties out of `n` total to decrypt
- **Zero-Knowledge Proofs**: Uses Fiat-Shamir transformed proofs for ciphertext validity
- **Efficient KZG Commitments**: Uses FK20 algorithm for quasi-linear time opening proofs
- **BLS12-381 Curve**: Built on arkworks cryptographic library

---

## Core Architecture & Components

### 1. Library Structure (`src/lib.rs`)
Simple module declaration file that exposes four main modules:
- `dealer` - Setup and key generation
- `decryption` - Partial and full decryption operations  
- `encryption` - Message encryption with proofs
- `utils` - Utility functions for cryptographic operations

### 2. Dealer Module (`src/dealer.rs`)

#### Core Structures:
- **`CRS<E: Pairing>`** - Common Reference String containing:
  - `powers_of_g: Vec<E::G1Affine>` - Powers of generator for KZG commitments
  - `htau: E::G2` - Structured reference string element
  - `y: Vec<E::G1Affine>` - Preprocessed Toeplitz matrix for batch opening proofs

- **`Dealer<E: Pairing>`** - Trusted setup authority with:
  - `batch_size: usize` - Number of ciphertexts per batch
  - `n: usize` - Total number of parties
  - `t: usize` - Threshold (t+1 parties needed to decrypt)
  - `sk: E::ScalarField` - Master secret key

#### Key Methods:
- **`new(batch_size, n, t)`** - Creates new dealer with random secret key
- **`get_pk()`** - Returns public key `g^sk`
- **`setup<R: RngCore>(rng)`** - Generates CRS and secret key shares
  - Samples random `tau` and computes powers
  - Generates Toeplitz matrix preprocessing for batch operations
  - Creates polynomial secret sharing of master key
  - Returns `(CRS, Vec<ScalarField>)` - the CRS and secret key shares

#### Cryptographic Details:
- Uses Lagrange interpolation for secret sharing
- Implements Toeplitz matrix optimization for batch KZG proofs
- FFT-based preprocessing for efficient batch operations

### 3. Encryption Module (`src/encryption.rs`)

#### Core Structures:
- **`DLogProof<F: PrimeField>`** - Zero-knowledge proof of discrete log knowledge:
  - `c: F` - Fiat-Shamir challenge
  - `z_alpha: F` - Opening for randomness α
  - `z_beta: F` - Opening for randomness β  
  - `z_s: F` - Opening for randomness s

- **`Ciphertext<E: Pairing>`** - Encrypted message with proof:
  - `ct1: [u8; 32]` - XOR-encrypted message
  - `ct2: E::G2` - Ciphertext component `h^{(τ-x)α}`
  - `ct3: E::G2` - Ciphertext component `h^α · pk^β`
  - `ct4: E::G2` - Ciphertext component `h^β`
  - `gs: E::G1` - Random group element `g^s`
  - `x: E::ScalarField` - Evaluation point
  - `pi: DLogProof<E::ScalarField>` - Validity proof

#### Key Methods:
- **`encrypt(msg, x, hid, htau, pk, rng)`** - Encrypts 32-byte message
  - Uses hash-to-curve for randomness generation with retry logic
  - Implements Fiat-Shamir proof system for ciphertext validity
  - Returns `Ciphertext<E>` with embedded zero-knowledge proof

- **`Ciphertext::verify(htau, pk)`** - Verifies ciphertext validity
  - Reconstructs commitment values from proof
  - Uses Merlin transcript for Fiat-Shamir challenge generation
  - Panics if verification fails

#### Cryptographic Protocol:
1. Sample randomness `s, α, β`
2. Compute mask using pairing: `e(H(id)/g^{H(g^s)}, h)^α`
3. XOR message with hash of mask
4. Generate proof of knowledge for `α, β, s`
5. Use Fiat-Shamir to make proof non-interactive

### 4. Decryption Module (`src/decryption.rs`)

#### Core Structures:
- **`SecretKey<E: Pairing>`** - Individual party's secret key share:
  - `sk_share: E::ScalarField` - This party's share of master secret

#### Key Methods:
- **`SecretKey::new(sk_share)`** - Creates secret key from share
- **`SecretKey::get_pk()`** - Returns this party's public key share
- **`SecretKey::partial_decrypt(ct, hid, pk, crs)`** - Computes partial decryption
  - Verifies all ciphertexts in batch
  - Computes polynomial commitment to hash values
  - Returns `E::G1` partial decryption share

- **`aggregate_partial_decryptions(partial_decryptions)`** - Combines shares
  - Uses Lagrange interpolation to recover full signature
  - Takes `BTreeMap<usize, G>` of party_id -> partial_decryption
  - Returns aggregated signature

- **`decrypt_all(sigma, ct, hid, crs)`** - Recovers all messages
  - Uses FK20 algorithm for efficient batch KZG opening proofs  
  - Computes pairings for each ciphertext
  - XORs with hash to recover original messages
  - Returns `Vec<[u8; 32]>` of decrypted messages

#### Decryption Protocol:
1. Each party computes partial decryption on batch
2. Combine sufficient partial decryptions via interpolation
3. Use aggregated signature and FK20 for batch opening
4. Decrypt each message using pairing computations

### 5. Utilities Module (`src/utils.rs`)

#### Core Functions:
- **`hash_to_bytes<T: CanonicalSerialize>(inp)`** - BLAKE3 hash to 32 bytes
- **`xor(a, b)`** - XOR two byte arrays
- **`add_to_transcript(ts, label, data)`** - Add data to Merlin transcript
- **`lagrange_interp_eval(given_domain, target_domain, evals)`** - Lagrange interpolation
- **`compute_opening_proof(crs, polynomial, point)`** - Single KZG opening proof
- **`open_all_values(y, f, domain)`** - FK20 batch opening algorithm

#### FK20 Implementation Details:
The `open_all_values` function implements the Feist-Khovratovich 2020 algorithm for computing all KZG opening proofs in O(n log n) time:
1. Constructs vector `v = {0, f₁, f₂, ..., fₐ, 0, ..., 0}`
2. Applies FFT to get frequency domain representation
3. Element-wise multiplication with preprocessed `y` values
4. Inverse FFT and truncation to get opening proofs

---

## Examples & Usage

### End-to-End Example (`examples/endtoend.rs`)
Complete demonstration of the protocol:
- **Setup**: Creates dealer, generates CRS and key shares for n=8 parties
- **Key Distribution**: Creates `SecretKey` objects for each party
- **Batch Encryption**: Encrypts same message at all points in evaluation domain
- **Partial Decryption**: n/2 parties compute partial decryptions
- **Aggregation**: Combines partial decryptions using Lagrange interpolation  
- **Full Decryption**: Recovers all messages and verifies correctness

**Usage:** `cargo run --example endtoend`

---

## Benchmarking Suite

### 1. Encryption Benchmark (`benches/encryption.rs`)
- **Purpose**: Measures single encryption performance
- **Parameters**: Batch sizes 4, 8, 16, 32 (encryption is independent of batch size)
- **Metrics**: Time per encryption operation
- **Note**: Serves as sanity check that batch size doesn't affect encryption time

### 2. Partial Decryption Benchmark (`benches/partial_decryption.rs`)  
- **Purpose**: Measures single party's partial decryption time
- **Parameters**: Batch sizes 4 to 1024 (2² to 2¹⁰)
- **Process**: 
  - Generates full batch of ciphertexts
  - Times single party's partial decryption computation
- **Sample Size**: 20 runs per configuration

### 3. Full Decryption Benchmark (`benches/decrypt_all.rs`)
- **Purpose**: Measures aggregation + full batch decryption
- **Parameters**: Batch sizes 4 to 1024  
- **Process**:
  - Generates partial decryptions from n/2 parties
  - Times aggregation + batch decryption process
- **Sample Size**: 20 runs per configuration

**Usage:** `cargo bench` (generates HTML reports in `target/criterion/`)

---

## Dependencies & Technical Stack

### Cryptographic Libraries:
- **arkworks ecosystem** (v0.5.0):
  - `ark-poly` - Polynomial operations and FFT
  - `ark-ff` - Finite field arithmetic  
  - `ark-ec` - Elliptic curve operations
  - `ark-serialize` - Serialization for crypto objects
  - `ark-bls12-381` - BLS12-381 curve implementation
- **blake3** (v1.0) - Fast cryptographic hashing
- **merlin** (v3.0) - Fiat-Shamir transcript library

### Utility Libraries:
- **retry** (v2.0) - Retry logic for hash-to-field operations
- **rand** (v0.8) - Random number generation
- **criterion** (v0.5) - Benchmarking framework with HTML reports

### Build Configuration:
- **Development Profile**: Optimized (`opt-level = 3`) for performance testing
- **Features**: Optional `asm` feature for assembly optimizations
- **Benchmark Harness**: Custom harness disabled for criterion integration

---

## Testing & Verification

### Unit Tests:

#### Dealer Tests (`src/dealer.rs`):
- **`test_dealer()`**: Verifies correct setup and key generation
  - Batch size: 32, parties: 16, threshold: 7
  - Validates secret key reconstruction via Lagrange interpolation
  - Confirms public key consistency across shares

#### Encryption Tests (`src/encryption.rs`):
- **`test_encryption()`**: Validates encryption and proof verification
  - Tests ciphertext serialization (compressed/uncompressed)
  - Measures component sizes (G1: 48 bytes, G2: 96 bytes compressed)
  - Verifies proof validation passes

#### Utility Tests (`src/utils.rs`):
- **`open_all_test()`**: Validates FK20 batch opening implementation
  - Creates random polynomial and computes all KZG proofs
  - Verifies each proof individually using pairing checks
- **`lagrange_interp_eval_test()`**: Tests polynomial interpolation
  - Evaluates random polynomial at test points
  - Compares direct evaluation vs interpolated results

### Integration Testing:
The `endtoend.rs` example serves as comprehensive integration test, validating the complete protocol flow from setup through decryption.

---

## Performance Characteristics

### Complexity Analysis:
- **Setup**: O(batch_size) for CRS generation
- **Encryption**: O(1) per message (independent of batch size)  
- **Partial Decryption**: O(batch_size log batch_size) due to FFT operations
- **Full Decryption**: O(batch_size log batch_size) using FK20 algorithm
- **Space**: O(batch_size) for CRS storage

### Benchmark Results Structure:
Results are stored in `target/criterion/` with HTML visualization:
- **encrypt/**: Single encryption timings across batch sizes
- **partial_decrypt/**: Partial decryption scaling from 4-1024 messages  
- **decrypt_all/**: Full batch decryption performance
- **report/**: Combined HTML dashboard with charts

---

## Security Model & Assumptions

### Trust Model:
- **Trusted Dealer**: Required for initial setup and key distribution
- **Threshold Security**: Requires t+1 parties to decrypt (where t < n/2)
- **Non-Interactive**: Uses Fiat-Shamir for proof generation

### Cryptographic Assumptions:
- **Bilinear Diffie-Hellman**: Security of pairing-based encryption
- **Discrete Logarithm**: Security in both G1 and G2 groups
- **Random Oracle**: For hash functions (BLAKE3)

### Implementation Notes:
- **Academic Prototype**: Not production-ready (per README warning)
- **No Side-Channel Protection**: Standard arkworks implementation
- **Deterministic Verification**: Proofs are deterministically verifiable

---

## Development & Extension Points

### Adding New Features:
1. **Different Curves**: Modify type aliases in examples/benchmarks
2. **Batch Size Scaling**: Adjust parameters in dealer creation
3. **Threshold Parameters**: Modify t/n ratios in setup
4. **Additional Benchmarks**: Follow existing benchmark patterns

### Code Structure for Extensions:
- **Modular Design**: Each component cleanly separated
- **Generic Implementation**: Works with any arkworks pairing
- **Trait-Based**: Easy to swap curve implementations

### Testing New Components:
- **Unit Tests**: Add to respective module files
- **Integration Tests**: Extend `endtoend.rs` example
- **Benchmarks**: Create new files following existing patterns

---

## Build & Run Commands

### Basic Operations:
```bash
# Run correctness test
cargo run --example endtoend

# Run all benchmarks  
cargo bench

# Build documentation
cargo doc --open

# Run unit tests
cargo test

# Build optimized release
cargo build --release
```

### Development Options:
```bash
# Enable assembly optimizations
cargo build --features asm

# Run specific benchmark
cargo bench --bench encryption

# Test with different batch sizes (modify source)
# Edit batch_size parameter in examples/benches
```

---

## File Structure Summary

```
src/
├── lib.rs              # Module declarations
├── dealer.rs           # Trusted setup & key generation  
├── encryption.rs       # Message encryption & proofs
├── decryption.rs       # Partial & full decryption
└── utils.rs           # Cryptographic utilities

examples/
└── endtoend.rs        # Complete protocol demonstration

benches/
├── encryption.rs      # Encryption performance
├── partial_decryption.rs  # Partial decryption scaling
└── decrypt_all.rs     # Full decryption benchmarks

Configuration:
├── Cargo.toml         # Dependencies & build config
├── README.MD          # Project overview & usage
└── LICENSE            # MIT license
```

This project provides a complete, benchmarked implementation of batched threshold encryption with extensive testing and performance analysis capabilities. The modular design makes it suitable for research, benchmarking, and as a foundation for building more complex threshold cryptographic systems.
