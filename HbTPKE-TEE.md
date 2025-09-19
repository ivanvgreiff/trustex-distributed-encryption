# Chair of Network Architectures and Services  
School of Computation, Information and Technology  
Technical University of Munich  

## Idea 1  
**Hybrid Batched Threshold Encryption with TEEs (HbTPKE-TEE)**  
Ivan von Greiff  
M.Sc Electrical and Information Engineering  

---

## 1 Motivation and Inspiration
The problem of mempool privacy has gained urgency with the rise of DeFi, where adversaries exploit transaction
visibility to frontrun, backrun, or censor users, leading to massive “Miner Extractable Value” (MEV) losses [1].
Existing threshold encryption approaches to protect the mempool (e.g., Shutter Network) either fall to
malleability attacks or sacrifice pending transaction privacy, leaking the content of transactions that never
make it on-chain.

To address these flaws, the old work *Mempool Privacy via Batched Threshold Encryption* introduced **bTPKE**
and the **FbTPKE** ideal functionality together with the first concretely efficient construction under that notion.  
The new work *Practical Mempool Privacy via One-time Setup Batched Threshold Encryption* then gives the first
practical one-time-DKG construction that removes per-epoch setup/MPC while preserving pending-transaction
privacy and O(1) per-server decryption communication.

The new one-time-DKG bTPKE construction eliminates per-epoch setup/MPC and keeps O(1) per-server decryption
communication; its main residual cost is the dominance of sigma-style proof and pairing checks during batch
decryption:

* a one-time DKG setup for the BLS key (no per-epoch setup), together with a reusable powers-of-τ CRS
  (e.g., from an existing ceremony); no MPC is required in the new construction.
* a decryption path whose dominant cost is verifying the sigma-style NIZK and pairing checks at realistic
  block sizes.

Importantly, while the authors dismiss TEE-only designs that entrust enclaves with long-term decryption keys,
they do not explore the possibility of TEEs as auxiliary accelerators in non-critical paths.  
This motivates our proposed hybrid extension of their ideal functionality—which we term **HbTPKE-TEE**—that
preserves one-time-DKG bTPKE’s strong cryptographic guarantees while allowing optional, attested TEE oracles
to offload exactly the two identified bottlenecks:

1. An **AttestedSetup** enclave that implements Setup, coordinating/attesting the one-time DKG and
   pins/aggregates PoT.
2. An **AttestedIngress** enclave that certifies ciphertext well-formedness and non-malleability at the network
   edge, replacing validators’ heavy sigma-style NIZK verification on the critical path.

This hybrid design maintains graceful fallback to pure cryptography when TEEs are distrusted, but enables
practical deployments by sharply reducing both setup costs and validator overhead.

## 2 Problem Statement
The work of Choudhuri et al. established batched-threshold encryption (bTPKE) and gave the first concretely
efficient construction that simultaneously achieves:
* Mempool privacy with CCA-style security (in ROM+AGM with straight-line extractability)
* Pending-transaction privacy
* O(1) per-server partial decryption (48 bytes) independent of B; total across n servers is O(n)

However, their construction inherits the two aforementioned major bottlenecks (cf. Section 1) that hinder
deployment in practice. We therefore pose the following problem:

How can one preserve the privacy and efficiency guarantees of the one-time-DKG bTPKE scheme for encrypted
mempools, while  
i) keeping the one-time DKG setup auditable and lightweight (no EpochSetup/MPC; reuse a public PoT CRS), and  
ii) removing per-transaction NIZK verification from the validator’s critical path,  
without ever entrusting TEEs with decryption capabilities or long-term secrets?

As we discuss in Section 10, these bottlenecks become particularly acute in real-world blockchain settings
(Ethereum, rollups, Cosmos/Tendermint), where block times and validator workloads impose strict performance
constraints.

---

## 3 Proposed Contribution
We propose **HbTPKE-TEE**, a hybrid extension of the one-time-DKG bTPKE execution model that introduces
two optional attested oracles. These oracles are designed to offload exactly the two bottlenecks identified
in one-time-DKG bTPKE—the expensive Setup phase and the validator CPU cost of sigma-style NIZKs
verification—without entrusting TEEs with decryption capabilities or long-term secrets.

If remote attestation fails or enclaves are distrusted, the system gracefully falls back to the baseline
one-time-DKG bTPKE protocol (pure cryptographic path), preserving all of the scheme’s privacy and efficiency
guarantees.

### AttestedSetup enclave
The AttestedSetup enclave coordinates and attests the one-time DKG (and optionally pins/aggregates
a reusable powers-of-τ CRS), without touching long-term keys. Concretely, it:
* orchestrates and attests the standard DKG that yields Shamir shares of the BLS key sk and publishes  
  `pk = h^sk` and `{h^[sk]_j}` (no party, enclave included, learns sk);
* aggregates/verifies contributions to a reusable powers-of-τ CRS (or pins to a well-known ceremony
  transcript);
* emits a remote-attestation quote binding the exact coordinator code and the resulting transcripts
  (DKG + PoT) to an append-only audit log.

Notably, it does **not** distribute `[Lj(γ)]` or any per-epoch state, and it does not produce per-epoch
commitments—those do not exist in the new protocol.

**Why this matters.**  
The new construction avoids per-epoch setup entirely and requires only a one-time DKG (plus a reusable
PoT CRS). Our AttestedSetup makes those steps operationally auditable without changing cryptographic trust
assumptions or introducing a TEE-held decryption key. Setup becomes practically cheap and auditable, lowering
the barrier to real-world deployment while keeping decryption unchanged and the protocol’s security intact.
Long-term trapdoors are never retained by the enclave (they are split, shared, and zeroized).

### AttestedIngress (Ciphertext Well-Formedness)
Ingress enclaves verify the sigma-style NIZKs attached to each ciphertext:  
(i) knowledge of encryption randomness, and  
(ii) knowledge of s with S = g^s such that t_g = H(S) (domain-separated by eid).

They also enforce per-epoch uniqueness of (x̂, t_g) (Bloom filter) to prevent copy/replay.  
Instead of requiring validators to verify all proofs and pairings, the enclave returns a compact attestation
```
σ_ing = Sign_TEE( H(eid ∥ x̂ ∥ S ∥ ct1 ∥ ct2 ∥ ct3 ∥ ct4 ∥ ts ∥ nonce) )
```

The enclave is responsible for:
* Verifying the sigma-style NIZKs Π1, Π2 for knowledge of encryption randomness and of s with S = g^s
* Checking t_g = H(S) (domain-separated by eid)
* Enforcing no duplicates of (x̂, t_g) in the epoch (Bloom filter) to prevent copy attacks

Validators then accept ciphertexts under the following policy:
1. `(ct, σ_ing, RA)` from a whitelisted attested ingress enclave, or
2. `(ct, π_NIZK)` verified in the standard cryptographic path.

To prevent copy and replay attacks, enclaves (or a shared filter) maintain per-epoch Bloom filters of signed
ciphertexts, refusing to re-sign variants of the same `(x̂, H(S))`. This directly addresses the “copy-attack”
the paper warns about.

**Validator fast-path.**  
In this model, validators verify only a lightweight TEE signature plus remote-attestation evidence per
transaction, rather than running full sigma-style NIZKs and pairing checks. The heavy cryptography is
offloaded to horizontally scalable ingress boxes, removing the dominant sigma-style proof and pairing
verification from the validator’s hot path.

**Security lens.**  
Under the honest-TEE assumption, the system enforces the same well-formedness and non-malleability
policy that sigma-style NIZKs provide. If TEEs are distrusted or attestation fails, nodes require sigma-style
NIZKs, restoring the scheme’s full cryptographic guarantees.

Together, the AttestedSetup and AttestedIngress provide a practical hybrid execution model: they preserve
bTPKE’s strong privacy and O(n) communication guarantees, while making setup lightweight and shifting
validator-critical verification off the hot path.  
**HbTPKE-TEE** thus offers a deployable balance between pure cryptography and trusted hardware,
with auditable TEEs as accelerators, not trust anchors.

## 4 Model, Assumptions, and Goals

### System Model
HbTPKE-TEE follows the execution model of one-time-DKG bTPKE with two optional attested oracles.  
The **AttestedSetup** is run once to coordinate and attest the DKG (and optionally pin/aggregate a PoT CRS);
it outputs attested transcripts of those ceremonies only (no per-epoch state).  
The **AttestedIngress** consists of enclaves deployed at the network edge (logically stateless, except for
per-epoch replay filters); clients submit ciphertexts to these enclaves, which certify well-formedness and
return signatures.  
Validators accept transactions carrying either enclave attestations or sigma-style NIZKs, ensuring liveness
even when TEEs are unavailable or distrusted.

### Adversary
We assume a network adversary that controls message scheduling and censorship; a Byzantine minority of
committee members; malicious clients submitting malformed ciphertexts; and attackers attempting TEE
compromise or remote-attestation (RA) forgery.  
Compromise of the RA root of trust (e.g., Intel/AMD root keys) is out of scope.

### Assumptions
We inherit the assumptions of the one-time-DKG bTPKE scheme (pairings/KZG in ROM+AGM with straight-line
extractability for the sigma-style proofs).  
We further assume sound remote attestation and that validators pin enclave measurements to an allowlist.  
TEEs never hold decryption keys or long-term secrets; any enclave state for setup is split/shared and then
zeroized, so compromise cannot retroactively break ciphertext privacy.

### Leakage Function L
We model the information exposed by attested oracles via a leakage function L, consistent with
oracle-augmented cryptographic definitions:
* **AttestedSetup:** observes (and attests to) DKG transcripts for sk (publishing pk = h^sk and {h^[sk]_j})
  and pins/aggregates a public PoT transcript; it does not learn sk or any long-term decryption material.
* **AttestedIngress:** learns ciphertext structure/metadata sufficient to check the well-formedness relation
  (the same information any sigma-style NIZKs verifier sees); it does not learn plaintexts or decryption keys.
* No additional leakage about non-decrypted ciphertexts across batching windows (epochs/blocks) is introduced.

### Security Objectives
1. **Privacy:** preserve pending-transaction privacy and CCA-style non-malleability in the same model as
   one-time-DKG bTPKE (ROM+AGM with straight-line extractability).
2. **Setup indistinguishability:** under sound RA and correct enclave code, outputs attested by
   AttestedSetup are indistinguishable from those of a correct non-TEE one-time DKG and PoT setup.
3. **Soundness-by-attestation:** accepting a σ_ing attestation is policy-equivalent to running the
   sigma-style NIZK verifier on the same relation, provided RA is sound and the ingress enclave enforces
   the specified checks.
4. **Graceful degradation:** revocation or rejection of RA forces fallback to the pure-cryptographic path
   (verifying the sigma-style proofs) with the existing one-time-DKG bTPKE (no TEEs).

### Non-goals
We do not attempt to reduce committee size n, protect against majority adversaries, or mitigate all TEE
side-channels.  
Our goal is to demonstrate that TEEs can serve as auditable accelerators for setup and ingress verification
without becoming trust anchors.

## 5 Potential Research Questions
* **RQ1 – Setup Efficiency.**  
  To what extent can AttestedSetup reduce operational cost and complexity of the one-time DKG (and PoT
  pinning) while keeping outputs verifiable and privacy-preserving?

* **RQ2 – Validator Performance.**  
  How much validator CPU and end-to-end block latency can be saved by replacing per-transaction sigma-style
  NIZK verification with AttestedIngress attestations, particularly at realistic block sizes B ∈ {128, 512}?

* **RQ3 – Security Equivalence.**  
  Under which precise assumptions does acceptance of a TEE attestation σ_ing provide the same non-malleability
  and CCA-style guarantees in the same model as one-time-DKG bTPKE (ROM+AGM with straight-line extractability)?

* **RQ4 – Robustness and Fallback.**  
  How reliably and with what latency overhead can HbTPKE-TEE revert to the pure-cryptographic path (the
  one-time-DKG bTPKE; PoT is public/reusable—no EpochSetup/MPC)?

* **RQ5 – Deployability.**  
  Does the hybrid design lower the barrier to adoption compared to pure-cryptographic one-time-DKG bTPKE,
  and what are the trade-offs between operational trust in TEEs and cryptographic guarantees?

## 6 Approach
Our approach combines empirical benchmarking with prototype enclave implementations, structured into clear
work packages that map directly to the research questions.

### A. Baseline Reproduction
We first reproduce the results of Choudhuri et al. to establish a trustworthy baseline.  
This includes verifying concrete metrics from the one-time-DKG bTPKE reference:
* ciphertext size adds ≈ **466 B** to the transaction for a 32 B message,
* partial decryptions: one G1 element (≈ **48 B**),
* encryption: ≈ **8.5 ms**,
* BatchDec: ≈ **3.2 s** at ~500 transactions,
* reconstruction: ≈ **3.0 s** at B = 512.

We confirm that the dominant cost in BatchDec is verifying the proofs and the pairing checks.  
This step ensures our evaluation of HbTPKE-TEE is grounded against the published reference implementation.

### B. Work Packages

**WP1: AttestedSetup (RQ1).**  
Implement the setup-coordinator logic inside a TEE.  
The enclave coordinates and attests a one-time DKG for sk (publishing pk = h^sk and {h^[sk]_j}), and
pins/aggregates a reusable PoT CRS transcript.  
An append-only audit log records  
`(enclave measurement, DKG transcript hash, pk, {h^[sk]_j}, PoT transcript ID, attestation)`.  
Public checks verify the DKG and PoT transcripts against the attestation.  
*Deliverables:* empirical comparison of setup time and operational complexity versus a non-TEE DKG baseline;
evidence that outputs are indistinguishable under sound RA.

**WP2: AttestedIngress (RQ2, RQ3).**  
Build RA-TLS ingress enclaves that validate ciphertext well-formedness and non-malleability relations
(as enforced in bTPKE via sigma-style NIZKs).  
Instead of proofs, they output compact attestations  
```
σ_ing = Sign_TEE( H(ct ∥ eid ∥ ts ∥ nonce) )
```
bound to all ciphertext components.  
Ingress enclaves maintain per-epoch Bloom filters to prevent re-signing of variants (anti-copy/replay).  
We begin with Ed25519/Schnorr signatures, with optional evaluation of threshold aggregation (FROST) for
scalability.  
*Deliverables:* benchmark of validator CPU savings at B ∈ {128, 512}; formal argument that acceptance of
σ_ing is policy-equivalent to sigma-style NIZK verification under sound RA.

**WP3: Node Policy and Fallback (RQ4).**  
Modify node acceptance policy so that validators accept either `(ct, σ_ing)` from whitelisted enclaves or
`(ct, π_NIZK)` verified cryptographically.  
If RA fails or is revoked, nodes immediately enforce sigma-style NIZK-only mode, preserving liveness and
privacy guarantees.  
*Deliverables:* evaluation of fallback latency and robustness under simulated revocation events.

## 7 Evaluation Plan
To assess whether HbTPKE-TEE achieves its intended benefits without weakening one-time-DKG bTPKE’s guarantees,
we will evaluate along three dimensions: **efficiency**, **security equivalence**, and **robustness**.

### Metrics
* **Efficiency:**  
  Setup wall-clock time and bytes; validator CPU during BatchDec; end-to-end block decryption latency;
  throughput (transactions per second).
* **Overheads:**  
  Attestation verification cost; network bytes and gossip-delay sensitivity (noting that additional KB beyond
  ~20 kB may impact propagation delay).
* **Robustness:**  
  Recovery latency when falling back to sigma-style NIZK-only mode upon RA failure or revocation.

### Experimental Environments
* **Microbenchmarks** of enclave vs. cryptographic components.
* **WAN emulation** (e.g., 200 ms delay, 20 ms jitter, 10 Mbit/s).
* Committee sizes **n ∈ {16, 64, 128}**.
* Batch sizes **B ∈ {128, 512}**.

### Baselines
1. **Pure-cryptographic one-time-DKG bTPKE** (as in Choudhuri et al.).
2. **Strawman TEE-only design** (keys inside enclave) for comparison only.
3. **HbTPKE-TEE** with AttestedSetup and/or AttestedIngress enabled.

### Hypotheses
* **H1:** AttestedSetup reduces setup cost by a large constant factor relative to a non-TEE DKG baseline,
  while producing outputs indistinguishable from an honest non-TEE DKG/PoT under sound RA.
* **H2:** AttestedIngress reduces validator CPU during BatchDec by **10×–100×**, yielding proportional
  reductions in block decryption latency at realistic batch sizes, with no loss of privacy or non-malleability
  guarantees.
* **H3:** The system degrades gracefully: revocation or failure of RA causes only short-lived performance loss,
  not liveness or security failure.

## 8 Risks and Mitigations

### TEE Compromise
HbTPKE-TEE never places long-term decryption keys inside enclaves.  
A compromised **AttestedSetup** cannot exfiltrate the secret key *sk* (generated via DKG), but could attempt to
mis-coordinate transcripts.  
Mitigations include:
1. Verifiable DKG transcripts,
2. Public PoT transcripts,
3. Automatic reversion to the pure-cryptographic path on attestation failure.

### Ingress Denial-of-Service
Ingress enclaves could become a bottleneck or target of denial-of-service attacks.  
Mitigations:
* Rate limiting,
* Committee-controlled allow-listing,
* Horizontal scaling of ingress TEEs.

Fallback to sigma-style NIZK-only verification (pure-crypto path) with the one-time-DKG bTPKE ensures liveness
even under sustained attack.

### Auditability and Accountability
All AttestedSetup outputs and ingress attestations are written to append-only logs.  
Committee members can cheaply validate the DKG and PoT transcripts with public checks.  
This ensures that even if TEEs misbehave, their influence is **detectable and attributable**.

## 9 Expected Contributions
* **Architecture:**  
  HbTPKE-TEE design with AttestedSetup and AttestedIngress oracles, including precise system model and
  formalized security goals. (addresses RQ1–RQ4)

* **Theory:**  
  Proof sketches showing  
  (i) indistinguishability of AttestedSetup outputs from a correct non-TEE one-time DKG/PoT setup, and  
  (ii) policy-equivalence of ingress attestations to sigma-style NIZK verification under sound RA.  
  (addresses RQ3)

* **Implementation:**  
  Prototype enclaves, node integration, and microbenchmarks demonstrating concrete setup and decryption-time
  improvements at Ethereum-scale batch sizes.  
  (addresses RQ1–RQ2)

* **Evaluation:**  
  End-to-end performance results across WAN emulation, varying committee/batch sizes, and fallback stress
  tests.  
  (addresses RQ2–RQ4)

* **Deployment Policy:**  
  A practical mempool policy that enforces clean fallback to pure cryptography on RA failure or revocation.  
  (addresses RQ4–RQ5)

* **Practical relevance:**  
  Analysis of deployment contexts (Ethereum, rollups, Cosmos) showing how HbTPKE-TEE optimizations map to
  validator workloads and MEV mitigation needs (Section 10).  
  (addresses RQ5)

## 10 Deployment Contexts and TEE-Based Optimizations
While HbTPKE-TEE is motivated by abstract efficiency and security goals, its true value lies in how it can be
deployed in real blockchain systems.  
Below we outline several representative contexts and show how our design’s optimizations reduce validator
workload, improve performance, and strengthen security in practice.

### 10.1 Ethereum and Layer-1 Context
Ethereum’s public mempool is the canonical setting for MEV attacks such as front-running and sandwiching.
An encrypted mempool based on HbTPKE-TEE would mitigate these issues by concealing transaction contents until
ordering is fixed.

The key optimization is that TEEs can offload heavy sigma-style NIZK verification:
rather than every validator performing hundreds of pairing or SNARK checks per block, a TEE verifies proofs
once and outputs a lightweight attestation. Validators then need only check a signature, yielding substantial
CPU savings and faster block propagation.

This aligns naturally with Ethereum’s proposer–builder separation, where block builders could operate enclaves
to decrypt after sealing, while proposers retain ordering control.  
Importantly, the hybrid design maintains decentralization while avoiding a pure TEE-only trust model:
decryption keys remain distributed, and enclaves only accelerate setup and proof-checking.

**Environment:**
* Large validator set (hundreds of thousands)
* Proposer–Builder Separation: builders assemble blocks, proposers choose among them
* Mempool is open/public, big MEV problem

**HbTPKE-TEE role:**
* **AttestedIngress** (TEE at network edge): verifies ciphertext well-formedness once, then attaches
  lightweight signatures instead of heavy sigma-style NIZKs. Validators save massive CPU time.
* **AttestedSetup:** less critical because Ethereum already has large-scale ceremonies (trusted setup/MPC)
  and initial setup is amortized across many validators. Existing public PoT transcripts can be reused
  (e.g., KZG PoT); AttestedSetup is less critical if a chain already standardizes on a well-known PoT.

**Key Benefit:**  
Scalability and fast block propagation (avoiding 2–3 seconds of validator CPU just for proof checks).

**Focus:**  
Validator’s workload in a very large, decentralized network.

---

### 10.2 Layer-2 Rollups and Sequencers
Rollups such as Optimism, Arbitrum, or zkSync rely on centralized or small-committee sequencers that are
natural points for MEV. In this context, a TEE-backed sequencer could:
1. Accept encrypted transactions,
2. Attest to validity,
3. Commit to block ordering before revealing plaintexts.

This prevents even a centralized operator from exploiting transaction data. Performance is also improved:
the enclave batches proof verifications and produces a single attestation, ensuring throughput is not
bottlenecked by cryptographic checks.

For zk-rollups, enclave attestations can be fed into zk-circuits as trusted inputs, avoiding the need to embed
costly cryptographic relations inside the SNARK. The result is MEV-resistant ordering with negligible latency
overhead.

**Environment:**
* Centralized or small-committee sequencers order transactions
* MEV risk is especially high, since a single sequencer can reorder everything
* Block times are short; high throughput is expected

**HbTPKE-TEE role:**
* **AttestedIngress:** runs at the sequencer front-end → transactions arrive encrypted, are attested by TEE
  (valid ciphertexts), but not decrypted until ordering is fixed.
* **AttestedSetup:** lightweight one-time setup, but because sequencers are few/centralized, this is less of a
  bottleneck.
* For zk-rollups, enclave attestations could even be inputs into zk-circuits (rather than all the heavy
  sigma-style NIZK verification logic), avoiding embedding expensive crypto checks inside the SNARK.

**Key Benefit:**  
Prevents sequencers from abusing privileged visibility (they do not see plaintext until block order is sealed).

**Focus:**  
Making centralized sequencers provably unable to frontrun/censor for MEV.  
In case of zk-rollups: efficiency of zk-proofs + MEV resistance.

---

### 10.3 Cosmos/Tendermint Chains
BFT-style PoS chains with 50–150 validators face distinct challenges:
1. Distributed key generation (DKG) protocols are communication-heavy and fragile,
2. Per-transaction proof verification is too slow for short block times.

HbTPKE-TEE addresses both.
A TEE-based dealer can perform DKG once (initially) and distribute shares with remote attestation, reducing a
complex multi-round MPC to a one-shot operation.
On the critical path, validator enclaves can pre-verify ciphertexts and output batch attestations, so other
validators only check signatures instead of hundreds of sigma-style NIZKs.
This can reduce verification cost by orders of magnitude (e.g., from ~0.5 s per 100 transactions to <1 ms).

Cosmos DeFi applications such as Osmosis would benefit from encrypted mempools that resist front-running,
with less operational burden than pure cryptographic schemes like Ferveo.
Unlike TEE-only approaches (e.g., Secret Network), HbTPKE-TEE still distributes decryption trust, combining
efficiency with decentralization.

**Environment:**
* Small-to-medium validator committees (50–150)
* Tendermint consensus requires multiple rounds of signed votes → communication cost is already high
* Block times are short (~6 s), validators cannot spend seconds per block verifying hundreds of heavy
  sigma-style NIZKs
* DKG ceremonies for threshold cryptography are very communication-heavy

**HbTPKE-TEE role:**
* **AttestedIngress:** pre-verifies ciphertexts and outputs batch attestations → validators only check
  signatures, not proofs. Essential for keeping block latency low.
* **AttestedSetup:** very important here → coordinates and attests a one-time DKG (and pins/aggregates a
  reusable PoT), avoiding complex multi-round MPC ceremonies.

**Key Benefit:**  
Lightens both setup and critical path costs in small committees.
Makes encrypted mempools feasible in BFT PoS systems where validator resources and block times are tight.

**Focus:**  
Operational simplicity for short block-time performance.

---

### 10.4 Summary
* **Ethereum:** Validator CPU for sigma-style NIZK dominates → **AttestedIngress is crucial**.
* **Rollups:** Sequencer fairness dominates → **AttestedIngress is crucial**.
* **Cosmos/Tendermint:** Setup/DKG cost dominates → **AttestedSetup is crucial**.
