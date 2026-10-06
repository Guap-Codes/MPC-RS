# Architecture Overview

MPC-RS is a distributed, zero-trust digital asset custody infrastructure designed for institutional use. It eliminates single points of failure by ensuring that no single machine, human, or process ever holds a complete private key.

## Core Design Philosophy: "Vault per DKG"
Unlike traditional HD wallets that derive millions of child keys from a single master seed, MPC-RS utilizes a **Vault per DKG** architecture for its primary secp256k1 chains (Bitcoin, Ethereum, Tron, XRP). 
- **1 DKG = 1 Unified Vault:** A single Distributed Key Generation (DKG) ceremony generates a master keypair that natively controls addresses across all secp256k1-based chains simultaneously.
- **Cryptographic Isolation:** Each treasury vault is an isolated cryptographic entity. A compromise or bug in one vault's transaction flow cannot mathematically impact another vault.
- **Simplified Key Management:** Eliminates the need for complex cross-curve BIP32/SLIP-10 derivation math inside the MPC protocol, reducing the attack surface.

## System Components

### 1. `mpc-api` (API Gateway)
The public-facing REST gateway that handles incoming transaction requests from internal applications or clients.
- **Responsibilities:** Request validation, scope-bound JWT authentication, rate limiting, blockchain state fetching (UTXOs/nonces), and transaction building.
- **Trust Boundary:** Untrusted network $\rightarrow$ Trusted internal network.

### 2. `mpc-coordinator` (Orchestrator)
The brain of the cluster. It does not hold any key material.
- **Responsibilities:** Session management, node routing, policy enforcement, and aggregating the final threshold signature.
- **Communication:** Speaks gRPC (mTLS) to the API Gateway and the MPC Nodes.

### 3. `mpc-node` (Cryptographic Engine)
The secure enclaves that hold the encrypted key shares.
- **Responsibilities:** Executing the CGGMP21 and FROST protocols, interacting with the Hardware Security Module (HSM), and generating partial signatures.
- **State:** Each node maintains an isolated, encrypted-at-rest local database (SoftHSM/YubiHSM) keyed by a master hardware key.

### 4. `mpc-protocol` (Cryptographic Core)
A pure-Rust implementation of the underlying threshold cryptography state machines.
- **CGGMP21:** For ECDSA (secp256k1).
- **FROST:** For EdDSA (ed25519 / Solana).

### 5. `blockchain-adapters`
Modular, chain-specific libraries that handle the idiosyncrasies of each blockchain (e.g., Bitcoin UTXO selection, Ethereum EIP-1559 gas estimation, Solana compute units).

## Data Flow: Transaction Signing
1. **Request:** Client sends a signed JWT to `mpc-api` requesting a transfer.
2. **Build:** `mpc-api` uses the relevant `blockchain-adapter` to fetch network state and build an unsigned transaction, extracting the cryptographic digest (sighash).
3. **Orchestrate:** `mpc-api` forwards the digest and vault metadata to `mpc-coordinator`.
4. **Route:** `mpc-coordinator` selects $t$ healthy nodes and initiates a P2P signing session via mTLS gRPC streams.
5. **Compute:** The selected `mpc-nodes` execute the MPC protocol, decrypting their shares from the HSM into secure memory, and compute a joint threshold signature.
6. **Aggregate:** Nodes report the final signature back to the `mpc-coordinator`.
7. **Broadcast:** `mpc-api` attaches the signature to the transaction and broadcasts it to the blockchain network.
