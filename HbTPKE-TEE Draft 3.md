Chair of Network Architectures and Services School of Computation,
Information and Technology Technical University of Munich Idea 1 Hybrid
Batched Threshold Encryption with TEEs (HbTPKE- TEE) Ivan von Greiff
M.Sc Electrical and Information Engineering 1 Motivation and Inspiration
The problem of mempool privacy has gained urgency with the rise of DeFi,
where adversaries exploit transaction visibility to frontrun, backrun,
or censor users, leading to massive "Miner Extractable Value" (MEV)
losses \[1\]. Existing threshold encryption approaches to protect the
mempool (e.g., Shutter Network) either fall to malleability attacks or
sacrifice pending transaction privacy, leaking the content of
transactions that never make it on- chain. To address these flaws,
Mempool Privacy via Batched Threshold Encryption (bTPKE) c.f. Link,
introduced a new primitive, batched-threshold encryption, which achieves
CCA-style non-malleability under ROM+AGM assumptions while achieving
O(n) decryption communication independent of batch size. This
construction represents the first "concretely efficient construction"
for their new notion (FbTPKE, the instantiation of bTPKE) designed to
solve the mempool privacy problem, but comes at a cost: • A
prohibitively heavy one-time Setup phase requiring either a trusted
dealer or an expensive one-time distributed key generation (DKG) plus a
power-of-τ common reference string (CRS) ceremony • A decryption path
dominated by simulation-extractable NIZKs and pairing checks (over 99%
of runtime for realistic block sizes). Importantly, while the authors
dismiss TEE-only designs that entrust enclaves with long-term decryption
keys, they do not explore the possibility of TEEs as auxiliary
accelerators in non-critical paths. This motivates our proposed hybrid
extension of their ideal functionality---which we term HbTPKE-TEE---that
preserves FbTPKE's strong cryptographic guarantees while allowing
optional, attested TEE oracles to offload exactly the two identified
bottlenecks: 1. An AttestedDealer enclave that implements Setup,
replacing the trusted dealer/MPC without touching long-term keys 2. An
AttestedIngress enclave that certifies ciphertext well- formedness and
non-malleability at the network edge, replacing validators' heavy
SE-NIZK verification on the critical path. This hybrid design maintains
graceful fallback to pure cryptography when TEEs are distrusted, but
enables practical deployments by sharply reducing both setup costs and
validator overhead. ... (content truncated for brevity in this code
cell) ...
