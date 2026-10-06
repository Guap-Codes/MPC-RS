# Threshold Cryptography Specifications

MPC-RS relies on state-of-the-art threshold signature schemes (TSS) to distribute trust. This document details the cryptographic primitives used.

## 1. CGGMP21 (secp256k1 / ECDSA)
Used for Bitcoin, Ethereum, Tron, and XRP. CGGMP21 (Canetti, Gennaro, Goldfeder, Makriyannis, Peled - 2021) is the industry standard for secure, identifiable-abort threshold ECDSA.

### Protocol Phases
1. **Auxiliary Information Generation (AuxGen):**
   - Nodes generate Paillier encryption keys and Ring-Pedersen commitment parameters.
   - *Note: This is computationally heavy (requires large prime generation and ZKPs) and is performed once per node lifecycle.*
2. **Distributed Key Generation (DKG):**
   - Nodes execute Feldman's Verifiable Secret Sharing (VSS).
   - Outputs: A shared public key $Q$ and individual secret shares $x_i$ such that $\sum x_i = x$ (the master private key).
3. **Presigning (Optional/Offline):**
   - Nodes pre-compute Beaver triples and random nonces $(k, \gamma)$ to speed up the online signing phase.
4. **Signing (Online):**
   - Given a message hash $m$, nodes engage in a 4-round MPC protocol to compute the ECDSA signature $(r, s)$ without ever reconstructing $x$ or $k$.
   - **Identifiable Abort:** If a node acts maliciously or drops offline, the protocol safely aborts and cryptographically identifies the faulty node.

## 2. FROST (ed25519 / EdDSA)
Used for Solana. FROST (Flexible Round-Optimized Schnorr Threshold signatures) is highly efficient for Schnorr/EdDSA curves.

### Protocol Phases
1. **DKG (Pedersen DKG):**
   - Generates the shared ed25519 public key and individual polynomial shares.
2. **Signing (2-Round Protocol):**
   - **Round 1 (Commitment):** Nodes generate and broadcast nonces.
   - **Round 2 (Challenge & Response):** Nodes compute the Schnorr challenge $c$ and their partial responses $z_i$, which are aggregated into the final signature $(R, z)$.

## 3. Zero-Knowledge Proofs (ZKPs)
To prevent malicious key generation or signing, MPC-RS enforces strict ZKPs at every network boundary:
- **Paillier Key Proof:** Proves the Paillier modulus $N$ is a product of two safe primes.
- **Ring-Pedersen Proof:** Proves the commitment parameters are well-formed.
- **MtA (Multiplicative-to-Additive) Proofs:** Prevents overflow and malicious value injection during the ECDSA multiplication steps.
