# Practical Mempool Privacy via One-Time Setup Batched Threshold Encryption

**Arka Rai Choudhuri*** (Nexus)  
**Sanjam Garg†** (UC Berkeley)  
**Guru-Vamsi Policharla‡** (UC Berkeley)  
**Mingyuan Wang§** (NYU Shanghai)

*arkarai.choudhuri@gmail.com. Part of this work was done while the author was a postdoc at NTT Research.*  
*†sanjamg@berkeley.edu*  
*‡guruvamsip@berkeley.edu*  
*§mingyuan.wang@nyu.edu. Part of this work was done while the author was a postdoc at UC Berkeley.*

---

## Abstract
An important consideration with the growth of the DeFi ecosystem is the protection of clients who submit transactions to the system. As it currently stands, the public visibility of these transactions in the memory pool (mempool) makes them susceptible to market manipulations such as frontrunning and backrunning. More broadly, for various reasons—ranging from avoiding market manipulation to including time-sensitive information in their transactions—clients may want the contents of their transactions to remain private until they are executed, i.e. they have pending transaction privacy. Therefore, mempool privacy is becoming an increasingly important feature as DeFi applications continue to spread.

We construct the first practical mempool privacy scheme that uses a one-time DKG setup for *n* decryption servers. Our scheme ensures the strong privacy requirement by not only hiding the transactions until they are decrypted but also guaranteeing privacy for transactions that were not selected in the epoch (pending transaction privacy). For each epoch (or block), clients can encrypt their transactions so that, once B (encrypted) transactions are selected for the epoch, they can be decrypted by each decryption server while communicating only O(1) information.

Our result improves upon the best-known prior works, which either:  
(i) require an expensive initial setup involving a (special purpose) multiparty computation protocol executed by the *n* decryption servers, along with an additional per-epoch setup;  
(ii) require each decryption server to communicate O(B) information; or  
(iii) do not guarantee pending transaction privacy.

We implement our scheme and find that transactions can be encrypted in approximately 8.5 ms, independent of committee size, and the communication required to decrypt an entire batch of transactions is 48 bytes per party, independent of the number of transactions. If deployed on Ethereum, which processes close to 500 transactions per block, it takes close to 3.2 s for each committee member to compute a partial decryption and 3.0 s to decrypt all transactions for a block in single-threaded mode. Compared to prior work, which had an expensive setup phase per epoch, we incur < 2× overhead in the worst case. On some metrics such as partial decryption size, we actually fare better.

---

## 1 Introduction
Decentralized Finance (DeFi) systems such as Ethereum allow users to submit transactions that will be executed in the next block. Submitted transactions are first propagated across the peer-to-peer network and collected in a *mempool* from which block proposers/validators choose a set of transactions to include in the next block. Because mempool contents are publicly visible, adversaries can exploit this visibility to mount various forms of market manipulation attacks.

One well-studied class of attacks is **Miner Extractable Value (MEV)**.  
Adversaries observe pending transactions and strategically insert their own transactions before or after (front-running or back-running) to extract value.  
Examples include sandwich attacks on decentralized exchanges, where an attacker profits from price slippage caused by the victim’s trade, and generalized frontrunning bots that automatically copy profitable trades.

These attacks harm honest users by increasing execution costs and destabilizing markets.  
The natural defense is to keep the content of transactions private until the block is finalized, so that adversaries cannot react before the ordering is fixed.  
However, protecting mempool privacy is challenging because validators still need to be able to verify and eventually execute the transactions.

### 1.1 Desired Properties
A practical mempool privacy mechanism should provide:

* **Pending-transaction privacy:**  
  The contents of transactions remain hidden until decryption after ordering.  
  Even transactions that are never included in a block should remain private.

* **One-time setup:**  
  The system should avoid expensive per-epoch ceremonies.  
  Ideally, there is a single distributed key-generation (DKG) that can support many epochs.

* **Low communication:**  
  Decryption of a batch of B transactions should require only O(1) communication per validator, not O(B).

* **Robustness and decentralization:**  
  Security should hold even if only a threshold of validators are honest, and there should be no single trusted dealer.

### 1.2 Existing Approaches and Their Limitations
Several threshold-encryption based approaches have been proposed to provide encrypted mempools:

* **Shutter Network** and related schemes encrypt each transaction so that validators jointly decrypt the selected batch.  
  These schemes either require heavy per-epoch setup, or fail to provide privacy for transactions that are never included.

* **[BO22]** achieves strong cryptographic guarantees but requires O(B) communication per validator during decryption, which is prohibitive for large blocks.

* **[CGPP24]** improves efficiency but still leaves some pending transactions vulnerable.

The lack of a scheme simultaneously achieving pending-transaction privacy, one-time setup, and O(1) communication motivates the work in this paper.

### 1.3 Our Contribution
We present the first *practical* construction of a **Batched Threshold Public-Key Encryption (bTPKE)** scheme that satisfies all three properties:

* It requires only a **one-time DKG** to set up the committee keys.
* Each validator communicates only **O(1)** data during decryption of an entire batch.
* It provides **CCA-style security** ensuring privacy for included and non-included transactions.

At a high level, our scheme introduces a new cryptographic primitive—**one-time setup batched threshold encryption**—and a concrete instantiation we call **FbTPKE** that meets these requirements.

The remainder of the paper develops the construction, analyzes its security, and reports on an experimental implementation demonstrating its practicality.

---

## 2 Technical Overview
We now give a high-level overview of our construction and how it achieves the desired properties.

### 2.1 Dream Goal
Suppose there are *n* decryption servers and a batch of B ciphertexts.  
The ideal functionality we would like is:

* **Setup:** a one-time DKG produces a public key and per-server secret keys.
* **Encryption:** each client encrypts a transaction under the public key.
* **Batch Decryption:** once a block of B ciphertexts is selected, each server outputs a short decryption share of size O(1).
* **Combine:** anyone can combine the n shares to recover all B plaintexts.

Moreover, the scheme should achieve **CCA security** and **pending transaction privacy**: ciphertexts not selected remain hidden even after others are decrypted.

### 2.2 Witness Encryption for Pairing Product Equations
A natural starting point is to view decryption as proving the existence of a witness to a certain pairing product equation.  
In particular, the decryptor knows Lagrange coefficients corresponding to the selected batch and can prove correct decryption via a succinct proof.  
This suggests using *witness encryption* (WE), but practical WE for complex pairing equations is not yet efficient enough.

### 2.3 First Attempt: BLS Signatures
To achieve short decryption shares, one might try to use BLS signatures.  
Each validator could sign a polynomial evaluation corresponding to its share, and the combiner could aggregate these signatures.  
However, naïve BLS aggregation does not directly yield the necessary batch decryption functionality because the combiner must still verify consistency across all ciphertexts.

### 2.4 Polynomial Encoding and KZG Commitments
Our key insight is to encode the B ciphertexts as evaluations of a polynomial f(x) over a structured domain (e.g., roots of unity).  
Validators hold shares of f at secret points and can produce proofs of correct partial decryption using **KZG commitments**.  
This allows the combiner to check consistency with only O(1) data per validator.

### 2.5 Shifted BLS Signatures
To obtain CCA security we need to prevent malleability of ciphertexts.  
We introduce *shifted BLS signatures*—a variant of BLS in which signatures are bound to an offset in the evaluation domain—so that an adversary cannot produce a valid ciphertext/decryption pair without the correct share.

### 2.6 Final Scheme
The final construction, which we call **FbTPKE**, combines these ingredients:

1. **Setup:**  
   *n* servers jointly run a one-time DKG to generate secret shares of a master key and a structured reference string for KZG commitments.

2. **Encryption:**  
   Clients encode their transactions as polynomial evaluations and publish KZG commitments and proofs of correctness.

3. **Batch Decryption:**  
   When a block of B ciphertexts is chosen, each validator outputs:
   * a constant-size KZG evaluation proof for its secret point,
   * a shifted BLS signature attesting to correct evaluation.

4. **Combine:**  
   Anyone verifies the proofs and reconstructs the plaintext batch using Lagrange interpolation.

This yields O(1) communication per validator, pending-transaction privacy, and CCA security in the random oracle plus algebraic group model.

---

## 3 Preliminaries
We review notation and cryptographic tools used in our construction.

### 3.1 Groups and Pairings
Let G1 and G2 be cyclic groups of prime order *p* with bilinear pairing  
e : G1 × G2 → GT.  
We write group operations multiplicatively and denote generators by g1 ∈ G1 and g2 ∈ G2.  
Security relies on standard assumptions such as the **k-Lin** or **SXDH** hardness assumptions.

### 3.2 Random Oracle Model (ROM)
We model hash functions as random oracles in the security proof, allowing the simulator to program outputs adaptively.

### 3.3 Algebraic Group Model (AGM)
To argue about pairing-based constructions we use the Algebraic Group Model, which requires adversaries to provide explicit representations of group elements as linear combinations of known generators.

### 3.4 Lagrange Polynomials
Given a set of B distinct points {x1,…,xB}, the Lagrange basis polynomial for point xi is  
```
Li(X) = ∏_{j≠i} (X - xj) / (xi - xj).
```
These polynomials satisfy Li(xj) = δij and are used to interpolate the encrypted batch.

### 3.5 KZG Commitments
A KZG commitment to a polynomial f over field F is a single group element
```
Com(f) = g1^{f(τ)}
```
where τ is a secret trapdoor known only during setup.  
Given a claimed evaluation f(a)=b, the prover can produce a constant-size proof π such that
```
e(Com(f) / g1^b , g2) = e(g1, g2^{τ - a}).
```
Verification requires only a pairing check.

### 3.6 Simulation-Extractable NIZKs
Our CCA-security proof requires simulation-extractable non-interactive zero-knowledge proofs (SE-NIZKs).  
These allow a simulator to create fake proofs while ensuring that any valid proof reveals the witness to an extractor.

### 3.7 Notation
For an integer n, we write [n] = {1,2,…,n}.  
Vectors are denoted in bold (e.g., **v**), and |x| denotes the bit-length of x.  
When an algorithm A outputs a pair (y, z) we write (y, z) ← A(·).

---

## 4 Model and Definitions
We now formalize the cryptographic primitive of *batched threshold encryption* and its security properties.

### 4.1 Syntax of Batched Threshold Encryption
A Batched Threshold Public Key Encryption (bTPKE) scheme for committee size n and threshold t consists of four algorithms:

* **Setup(1^λ, n, t)** → (pk, {ski}i∈[n]):  
  A one-time distributed key generation protocol run by all n validators that outputs a public key pk and a secret key share ski for each validator i.

* **Enc(pk, m)** → ct:  
  A probabilistic encryption algorithm that takes a message m and outputs a ciphertext ct.

* **BatchDec(i, ski, S, {ctj}j∈S)** → σi:  
  Given a subset S of ciphertexts (|S| = B), validator i uses its secret share to compute a constant-size decryption share σi for the entire batch.

* **Combine(S, {σi}i∈T)** → {mj}j∈S:  
  Given decryption shares from any subset T ⊆ [n] of size at least t, output the plaintexts for all ciphertexts in S.

Correctness requires that for any honestly generated keys and any batch of ciphertexts, Combine using any t valid shares outputs the correct messages.

### 4.2 Efficiency Requirements
A key feature of our primitive is that each decryption share σi must be of **constant size independent of B**, and the Combine algorithm should use **O(B log B)** group operations.  
This ensures scalability to large blocks without increasing validator communication.

### 4.3 Pending Transaction Privacy
The scheme must protect the privacy of *all* ciphertexts, including those not chosen for decryption in a given epoch.  
Formally, even if an adversary adaptively corrupts up to t−1 validators and obtains their secret shares, it cannot distinguish encryptions of chosen messages from random, unless those ciphertexts are among the decrypted batch.

### 4.4 CCA Security
To resist malleability and replay attacks, we require a strong chosen-ciphertext attack (CCA) notion tailored to the batched setting.  
Intuitively, the adversary may submit ciphertexts of its choice and obtain decryption shares for arbitrary batches, but cannot learn any information about the plaintext of a challenge ciphertext even if it overlaps with other batches, provided at least one honest validator remains.

The formal game proceeds as follows:

1. **Setup:** Challenger runs Setup and gives pk to the adversary.
2. **Phase 1:** Adversary adaptively queries a decryption oracle on batches of ciphertexts and corrupted key shares (up to t−1).
3. **Challenge:** Adversary submits two equal-length message vectors. Challenger encrypts one at random and returns the ciphertexts.
4. **Phase 2:** Continued adaptive queries, with the restriction that the challenge ciphertexts cannot be directly queried.
5. **Guess:** Adversary outputs a bit b′. Advantage is |Pr[b′=b] − 1/2|.

A scheme is secure if this advantage is negligible.

### 4.5 Ideal Functionality FbTPKE
For security proofs we define an ideal functionality **FbTPKE** that captures the intended behavior of batched threshold encryption in the universal composability (UC) framework.  
FbTPKE maintains a registry of ciphertexts and their plaintexts, responds to encryption and decryption requests, and ensures that:

* Decryption of a batch reveals exactly the messages in that batch.
* Non-selected ciphertexts remain hidden forever.
* Decryption shares can be simulated without revealing plaintexts.

A real-world protocol securely realizes FbTPKE if every attack in the real world can be simulated in the ideal world.

---

## 5 Construction
We now describe our concrete construction of a batched threshold public key encryption (bTPKE) scheme that satisfies the definitions in Section 4.  
The scheme—called **FbTPKE**—combines polynomial encoding, KZG commitments, and shifted BLS signatures to achieve constant-size decryption shares, pending transaction privacy, and CCA security.

### 5.1 Setup
The *n* validators jointly run a one-time distributed key generation (DKG) protocol to sample:
* a pairing-friendly bilinear group (G1, G2, GT) of prime order p with generators g1 ∈ G1 and g2 ∈ G2,
* a secret τ ∈ Fp used to generate a structured reference string for KZG commitments,
* a threshold t Shamir sharing of a secret master key α ∈ Fp.

Each validator i obtains a secret key share ski = αi and a public verification key vki = g2^{αi}.  
The committee publishes the public key pk = g1^α and the KZG commitment parameters
```
crs = (g1, g1^τ, g1^{τ^2}, … , g1^{τ^B}, g2, g2^τ).
```
The trapdoor τ is erased after setup.

### 5.2 Message Encoding
Transactions are first mapped to field elements using a collision-resistant hash Hmsg.  
To encrypt a batch of B transactions, we view them as evaluations of a polynomial f of degree < B at a fixed domain {ω1,…,ωB} of Bth roots of unity.  
Specifically, f(ωj) = mj for j ∈ [B].

### 5.3 Encryption
To encrypt a single message m:
1. Sample random r ← Fp.
2. Compute x̂ = Hmsg(m) (a public descriptor of the message).
3. Compute KZG commitment C = g1^{f(τ)} to a polynomial f such that f(x̂) = m.
4. Compute shifted BLS signature σ = g1^{(α + δ x̂) r} for random shift δ.

The ciphertext is
```
ct = (x̂ , C , π , σ , aux)
```
where π is a KZG proof of correct evaluation and aux contains domain identifiers needed for batch reconstruction.

### 5.4 BatchDecryption
Given a selected batch S of B ciphertexts, validator i performs:
1. Compute evaluation f(γi) of the polynomial encoding the batch at its secret point γi.
2. Compute KZG evaluation proof πi for correctness.
3. Output decryption share
```
σi = g1^{αi f(γi)}  ∥  πi .
```
Each share is a constant-size element of G1 plus a proof.

### 5.5 Combine
Anyone collecting valid decryption shares from any t validators can:
1. Verify each share using the KZG proof πi and the public verification key vki.
2. Interpolate the polynomial f over the structured domain {ω1,…,ωB} using the t valid evaluations {f(γi)} to recover all B plaintexts.

The Combine algorithm runs in O(B log B) group operations due to the use of FFT-style interpolation.

### 5.6 Correctness
By properties of Shamir sharing and KZG commitments, any set of t valid shares uniquely determines the polynomial f and hence all B messages.  
The evaluation proofs guarantee that incorrect shares are detected.

### 5.7 Security Intuition
* **Pending-transaction privacy:**  
  Non-selected ciphertexts remain information-theoretically hidden because no decryption shares for them are ever released.

* **CCA security:**  
  Shifted BLS signatures bind ciphertexts to the hidden exponent α, preventing malleability.  
  Simulation-extractable NIZKs allow the simulator to produce fake proofs in the security reduction while ensuring that any valid proof reveals the underlying witness.

* **Efficiency:**  
  Each validator broadcasts only O(1) group elements independent of B.  
  Combine runs in O(B log B) thanks to FFT interpolation.

### 5.8 Public Parameters
For clarity, the global parameters of FbTPKE are:

* Group description (G1, G2, GT, e, p)
* Generators g1, g2
* Structured reference string (g1^{τ^k}, g2^{τ}) for k=1,…,B
* Hash functions Hmsg, Hproof modeled as random oracles
* Security parameter λ
* Committee size n and threshold t
* Evaluation domain {ω1,…,ωB}

These parameters are established during the one-time setup and reused for all epochs.

---

## 6 Implementation and Evaluation
We implemented our FbTPKE construction in **Rust** using the `arkworks` and `merlin` cryptographic libraries.  
All experiments were run on a **2019 MacBook Pro** with a 2.4 GHz Intel Core i9 CPU and 16 GB of RAM.  
Unless otherwise specified, timing measurements represent the mean over 50 trials.

### 6.1 Ciphertext Size
Each ciphertext contains:
* one element of G1,
* three elements of G2,
* four field elements,
* a 2-byte descriptor x̂,
* a 32-byte message tag.

This totals approximately **498 bytes per ciphertext** for 32-byte messages, independent of committee size or batch size.

### 6.2 Encryption Time
Encryption time is independent of committee size.  
A single encryption requires roughly **8.5 ms** to compute.

### 6.3 Partial Decryption and Reconstruction
The dominant cost is batch decryption.  
Table 1 summarizes the cost for various batch sizes B, averaged over n = 16 validators.

| Batch size B | Partial Decryption Time (ms) | Reconstruction Time (ms) |
|--------------|-------------------------------|---------------------------|
| 8            | 49.2                          | 60.5                      |
| 32           | 199.8                         | 168.1                     |
| 128          | 809.9                         | 646.1                     |
| 512          | 3203.9                        | 3026.5                    |

*Partial decryption* is the time for a single validator to compute its decryption share.  
*Reconstruction* is the time for the combiner to recover all B plaintexts from t = 11 valid shares.

For an Ethereum-like block containing **≈500 transactions**, single-threaded reconstruction takes **≈3.0 seconds**, and each validator spends **≈3.2 seconds** computing its partial decryption.

### 6.4 Communication Cost
Partial decryption shares are a single G1 element (48 bytes) plus a constant-size proof.  
This is roughly **40% smaller** than the partial decryption size in [CGPP24] while remaining constant in B.

The total communication for decryption is thus **48 bytes × n** per block, independent of the number of transactions B.

### 6.5 Comparison with Prior Work
The following table compares ciphertext size and decryption communication with prior encrypted-mempool schemes:

| Parameter                    | [BO22] | [MGZ22, Shu21] | [CGPP24] | **This Work** |
|-------------------------------|-------:|---------------:|--------:|--------------:|
| Increase in Ciphertext Size   | \|G1\|+\|G2\| | \|G2\| | 2\|G2\|+\|G1\|+3\|F\|+2 | 3\|G2\|+\|G1\|+4\|F\|+2 |
| Size of Partial Decryptions   | nB\|G1\| (≈3 MB) | n\|G1\| (≈6 KB) | n(\|G1\|+\|F\|) (≈10 KB) | n\|G1\| (≈6 KB) |
| Partial Decryptions / Block   | 500%   | 1%            | 2%      | **1%** |

Our scheme requires no per-epoch setup and communicates less than 1% of the block size.

### 6.6 Committee Churn
Validator committees may change over time.  
To handle churn we use *proactive secret sharing* to refresh secret keys without revealing the master secret α.  
Benchmarks show that a full key refresh for n = 64 validators completes in **<10 seconds** over a wide-area network, which is negligible compared to epoch duration.

### 6.7 Implementation Takeaways
* Encryption is fast and independent of committee size.  
* Decryption dominates runtime but remains practical for Ethereum-scale batches.  
* Communication cost is nearly minimal: 48 bytes per validator per block.

These results demonstrate that FbTPKE can be deployed in real-world blockchain systems to provide mempool privacy without sacrificing throughput or decentralization.

---

## 7 Security Proof
We now outline the proof that our construction securely realizes the ideal functionality **FbTPKE** defined in Section 4.  
Our proof proceeds in the **programmable Random Oracle Model (ROM)** and the **Algebraic Group Model (AGM)**.

### 7.1 Proof Strategy
The goal is to show that any probabilistic polynomial-time adversary \(\mathcal{A}\) attacking the real-world protocol can be transformed into an adversary that breaks a standard hardness assumption with only negligible advantage.

The proof follows a sequence of hybrid games:
* **H0:** The real execution of the protocol.
* **H1:** Replace random oracles with simulated oracles that record all queries.
* **H2:** Program the oracles to embed a challenge instance of the k-Lin or i-KZG assumption.
* **H3:** Extract algebraic representations of all adversarial group elements as required by the AGM.
* **H4:** Replace genuine encryption of challenge messages with encryptions of random messages.
* **H5:** Simulate decryption shares for non-challenge batches using extractor outputs.
* **H6:** Remove dependence on the actual plaintexts of challenge ciphertexts.

Indistinguishability between successive hybrids relies on the k-Lin hardness in the target group and the simulation-extractability of the NIZK proofs.

### 7.2 Simulation-Extractable NIZKs
We employ SE-NIZKs to prove correctness of KZG evaluations.  
Simulation soundness ensures that proofs created by the simulator are computationally indistinguishable from honestly generated proofs, while extractability guarantees that any valid proof reveals the underlying witness.

This allows the simulator to respond to adversarial decryption queries without knowing the actual messages.

### 7.3 Algebraic Group Model
In the AGM, any adversary outputting a group element must also provide a representation of that element as a linear combination of previously seen group elements.  
This property allows the simulator to extract the coefficients used in ciphertexts and decryption shares, which are crucial for the reduction.

### 7.4 Key Lemmas
**Lemma 1 (Hybrid Indistinguishability).**  
If the k-Lin assumption holds in G1 and G2, then no polynomial-time adversary can distinguish hybrids H0,…,H6 with non-negligible advantage.

**Lemma 2 (CCA Security).**  
Under the same assumptions, the advantage of any adversary in the CCA game of Section 4.4 is negligible.

The proof of Lemma 2 uses Lemma 1 together with a standard reduction showing that breaking the CCA game would contradict indistinguishability of the hybrids.

### 7.5 Main Theorem
**Theorem 5.**  
Let λ be the security parameter.  
Assume the hardness of the k-Lin problem and the existence of simulation-extractable NIZKs in the ROM+AGM.  
Then the protocol FbTPKE securely realizes the ideal functionality FbTPKE with negligible advantage in λ.

*Proof Sketch.*  
Consider an adversary \(\mathcal{A}\) that distinguishes between the real and ideal executions.  
Using Lemmas 1 and 2 we construct an algorithm \(\mathcal{B}\) that solves k-Lin with non-negligible probability, contradicting the assumption.

### 7.6 Discussion
Our proof shows that **pending transaction privacy** and **CCA-style non-malleability** hold simultaneously:
* Even ciphertexts that are never selected for decryption remain hidden.
* Any attempt to modify a ciphertext without the correct witness will be rejected.

The combination of ROM and AGM is standard for pairing-based protocols and is necessary to extract linear representations of adversarial group elements while allowing random oracle programmability.

---
