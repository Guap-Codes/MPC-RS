# MPC-RS

**A production-grade, multi-party computation (MPC) wallet infrastructure for institutional digital asset custody.**

MPC-RS is a pure Rust implementation of a threshold-signature wallet system that enables secure, distributed key management across multiple blockchain networks. By splitting private key material into encrypted shares distributed across independent nodes, MPC-RS eliminates single points of failure and removes the need for any single party to hold a complete private key.

---

## Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────┐
│                         Users / Applications                    │
└──────────────────────────────┬──────────────────────────────────┘
                               │ REST / gRPC
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    mpc-coordinator (Orchestrator)               │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Session Mgmt │  │ Auth (JWT)   │  │  Drain Orchestrator    │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
└──────────────────────────────┬──────────────────────────────────┘
                               │ gRPC (mTLS)
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
┌──────────────────┐ ┌──────────────────┐ ┌──────────────────┐
│    mpc-node 1    │ │    mpc-node 2    │ │    mpc-node 3    │
│  ┌────────────┐  │ │  ┌────────────┐  │ │  ┌────────────┐  │
│  │ Key Share  │  │ │  │ Key Share  │  │ │  │ Key Share  │  │
│  └────────────┘  │ │  └────────────┘  │ │  └────────────┘  │
│  ┌────────────┐  │ │  ┌────────────┐  │ │  ┌────────────┐  │
│  │ HSM Backend│  │ │  │ HSM Backend│  │ │  │ HSM Backend│  │
│  │ (Isolated) │  │ │  │ (Isolated) │  │ │  │ (Isolated) │  │
│  └────────────┘  │ │  └────────────┘  │ │  └────────────┘  │
└──────────────────┘ └──────────────────┘ └──────────────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │ P2P (MPC Protocol)
                              ▼
                    ┌──────────────────┐
                    │  mpc-protocol    │
                    │ (CGGMP21/FROST)  │
                    └──────────────────┘
```

---

## Features

### Threshold Cryptography
- **CGGMP21 Protocol**: State-of-the-art threshold ECDSA signing for secp256k1 curves (Bitcoin, Ethereum, Tron, XRP).
- **FROST Protocol**: Threshold Schnorr/EdDSA signing for ed25519 curves (Solana) using an "Account-per-Vault" on-demand DKG model.
- **Proactive Key Refresh**: Rotate secp256k1 key shares without changing the master public key or requiring fund migration (n-of-n).
- **Identifiable Abort**: Malicious or faulty nodes are identified and excluded during signing.

### Unified Multi-Chain Vaults (Vault-per-DKG)
Because Bitcoin, Ethereum, Tron, and XRP all utilize the **secp256k1** elliptic curve, a single Distributed Key Generation (DKG) session natively generates valid master addresses for all four chains simultaneously.
- **Zero-Config Address Generation**: Nodes automatically calculate and log the Master Addresses for BTC, ETH, TRX, and XRP immediately upon DKG completion.
- **Vault-per-DKG Model**: Institutional-grade security where every new treasury vault is an isolated, mathematically distinct DKG session. Funds are sent directly to the Master Address, and drained using an empty derivation path.
- **Hot/Cold Split Architecture**: The system intentionally decouples the MPC Cold Vault from daily operational overhead. The API Gateway uses a separate, configurable `MASTER_XPUB` (in `.env`) to generate unique, monitored deposit addresses and to receive transaction change. This isolates the MPC nodes from address-generation logic and creates a natural, secure sweep mechanism for leftover funds.

### Multi-Chain Support
| Blockchain | Curve     | Signature Scheme| Protocol   | Adapter           |
|------------|-----------|-----------------|------------|-------------------|
| Bitcoin    | secp256k1 | ECDSA           | CGGMP21    | `bitcoin-adapter` |
| Ethereum   | secp256k1 | ECDSA           | CGGMP21    | `ethereum-adapter`|
| Tron       | secp256k1 | ECDSA           | CGGMP21    | `tron-adapter`    |
| XRP Ledger | secp256k1 | ECDSA           | CGGMP21    | `xrp-adapter`     |
| Solana     | ed25519   | EdDSA           | FROST      | `solana-adapter`  |

### Security
- **Hardware Security Modules (HSM)**: Native support for YubiHSM 2, AWS CloudHSM, Azure Managed HSM, and SoftHSM (development).
- **Automated HSM Isolation**: Nodes dynamically isolate their HSM databases into node-specific directories at runtime, preventing cross-node state corruption.
- **mTLS Everywhere**: All inter-service communication uses mutual TLS with certificate pinning.
- **Scope-Bound JWT Authentication**: Strict audience validation prevents cross-service token replay attacks.
- **Zero-Trust Architecture**: No single component holds a complete private key.

### Key Rotation Strategy & Limitations
- **Native Rotation Limitation**: Cryptographic share refresh (rotation) is currently **only supported for `n-of-n` vaults** (e.g., a 3-of-3 setup). It is *not* supported for threshold `t-of-n` vaults (e.g., 2-of-3) due to underlying constraints in the `cggmp21` protocol implementation.
- **Migration Rotation (Recommended)**: For threshold vaults, MPC-RS enforces an industry-standard "Migration Rotation" strategy to achieve forward secrecy:
  1. **Generate**: Run a fresh DKG ceremony to create a new, isolated vault.
  2. **Transfer**: Use the MPC network to sign a transaction that sweeps all funds from the old vault to the new vault.
  3. **Decommission**: Securely delete the old key shares from all nodes' HSMs.
- **Security Guarantee**: This approach provides the exact same security outcome as native rotation. Any previously compromised shares from the old vault are rendered completely useless because the vault no longer holds any funds.

---

## Quick Start

### 1. Clone and Build
```bash
git clone https://github.com/guap-codes/mpc-rs.git
cd mpc-rs
cargo build --release
```

### 2. Generate TLS & JWT Keys
```bash
openssl genrsa -out config/private.pem 4096
openssl rsa -in config/private.pem -pubout -out config/public.pem
./scripts/generate-certs.sh
```

### 3. Start the Cluster
```bash
./run-local.sh
```

### 4. Authenticate & Bootstrap the Vault
```bash
# 1. Generate a 24-hour admin JWT scoped to the Coordinator
export MPC_TOKEN=$(./target/release/mpc-cli dev-token --audience mpc-coordinator)

# 2. Run AuxGen (Takes 5-15 minutes of heavy CPU usage)
./target/release/mpc-cli --config config/admin.toml aux-gen

# 3. Once nodes log "AuxInfo generated successfully", run DKG
./target/release/mpc-cli --config config/admin.toml keygen \
  --curve secp256k1 \
  --threshold 2
```
*Check `logs/node1.log`. You will see the unified Master Addresses for Ethereum, Bitcoin, Tron, and XRP printed automatically.*

```bash
# 4. Generate a Solana (Ed25519) vault using FROST DKG
./target/release/mpc-cli --config config/admin.toml solana-keygen
```

---

## Admin CLI Reference

```text
ENVIRONMENT:
    MPC_TOKEN              Required JWT for authenticated commands.

SUBCOMMANDS:
    dev-token       Generate a scope-bound JWT (--audience mpc-coordinator|mpc-api)
    aux-gen         Generate AuxInfo (Paillier/RSA keys) for all nodes (One-time setup)
    keygen          Initiate Distributed Key Generation (DKG) for Unified Multi-Chain Vault
    solana-keygen   Generate a new Solana (Ed25519) vault using FROST DKG
    rotate          Trigger proactive key share refresh
    status          Check health of coordinator and nodes
    backup          Request encrypted share backups from all nodes
    drain           Emergency break-glass: drain funds to cold storage (Supports all chains)
                    Usage: drain --chain <chain> --from-address <addr> --target-address <addr> --derivation-path ""
```

---

## Formal Verification (Kani)

MPC-RS prioritizes mathematical correctness and memory safety. Core cryptographic and protocol logic in `mpc-core` and `mpc-protocol` is verified using [Kani](https://model-checking.github.io/kani/), a bit-precise model checker for Rust that proves the absence of panics, overflows, and memory safety violations.

### Prerequisites
1. Install the Kani verifier:
   ```bash
   cargo install --locked kani-verifier
   cargo kani setup
   ```

### Running Verification
To verify the core cryptographic and session management logic:
```bash
# Verify the entire workspace (may take several minutes)
cargo kani --workspace

# Or verify specific critical crates
cargo kani -p mpc-core
cargo kani -p mpc-protocol
```
*Note: Kani proofs are integrated into the CI/CD pipeline to prevent regressions in safety-critical code paths.*

---

## Roadmap

MPC-RS is under active development. Below is the high-level roadmap for upcoming features and enhancements:

### Short-Term (Q1-Q2)
- [x] Unified Multi-Chain Vaults (secp256k1 DKG for BTC, ETH, TRX, XRP).
- [x] FROST DKG and Signing for Ed25519 (Solana).
- [ ] **Advanced Policy Engine**: Implement stateful rules (e.g., rolling 24h volume limits via Redis) and multi-approver JWT workflows.
- [ ] **Expanded Chain Support**: Add native adapters for Cosmos (secp256k1), Polkadot (sr25519), and Layer 2 rollups (Arbitrum, Optimism).

### Mid-Term (Q3-Q4)
- [ ] **Formal Verification**: Expand Kani model checking coverage to 100% of `mpc-core` state transitions and message serialization logic.
- [ ] **Hardware Attestation**: Integrate AWS Nitro Enclaves or Intel SGX remote attestation to prove node execution environments are untampered.
- [ ] **Key Share Recovery**: Implement Shamir's Secret Sharing (SSS) based recovery workflows for lost HSM backups, requiring M-of-N admin approval.

### Long-Term (Future)
- [ ] **Decentralized Coordinator**: Replace the centralized `mpc-coordinator` with a BFT consensus layer (e.g., Tendermint/CometBFT) to eliminate the orchestrator as a single point of coordination failure.
- [ ] **DeFi Protocol Integration**: Native support for MPC-driven interactions with complex smart contracts (e.g., Uniswap swaps, Aave lending) via transaction simulation and calldata generation.
- [ ] **Post-Quantum Readiness**: Evaluate and integrate lattice-based threshold signature schemes for future-proofing.

---

## Security Considerations

- **Never store private keys in plaintext.** All key shares are encrypted at rest using the configured HSM backend.
- **Use hardware HSMs in production.** SoftHSM is for development only.
- **Keep the coordinator air-gapped from the public internet.** Only expose the API gateway through a reverse proxy with WAF.
- **Enforce strict JWT audiences.** Never use a token generated for `mpc-api` to authenticate against `mpc-coordinator` administrative endpoints.
- **Understand the Hot/Cold Split.** The `MASTER_XPUB` in `.env` is your operational hot wallet hierarchy. Do not confuse it with the MPC Cold Vault addresses generated during DKG.
