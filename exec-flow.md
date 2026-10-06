# MPC-RS Execution Flow

Here is the complete end-to-end execution flow for the **Vault per DKG** architecture. In this model, one DKG session creates one unified, multi-chain treasury vault, operating in a secure Hot/Cold split with the API Gateway.

---

## Phase 0: Build & Prerequisites

### 1. Compile All Binaries
```bash
cargo build --release
```

# Optional but highly recommended: Run formal verification on core cryptographic logic
# Requires `cargo kani` to be installed (see README.md)
cargo kani -p mpc-core -p mpc-protocol

### 2. Generate TLS Certificates & JWT Keys
```bash
# Generate RSA keys for JWT signing
openssl genrsa -out config/private.pem 4096
openssl rsa -in config/private.pem -pubout -out config/public.pem

# Generate mTLS certificates for the cluster
./scripts/generate-certs.sh
```

### 3. Configuration Files
*(Ensure your `config/nodeX.toml` files are set up. The node engine automatically overrides the `share_label` at runtime to isolate HSM databases into `data/node{X}/`, preventing cross-node state corruption.)*

> **Note on `MASTER_XPUB`**: The `MASTER_XPUB` in your `.env` file configures the API Gateway's **Hot Wallet** hierarchy. It is used exclusively to generate unique deposit addresses for monitoring and to receive transaction change. It is mathematically independent of the MPC Cold Vault generated during DKG.

---

## Phase 1: Infrastructure Startup

### Step 1: Start the Cluster
```bash
./run-local.sh
```

---

## Phase 2: Cryptographic Bootstrap

### Step 2: Authenticate CLI
```bash
# Token for Coordinator (DKG, AuxGen, Status, Drain)
export MPC_TOKEN=$(./target/release/mpc-cli dev-token --audience mpc-coordinator)
```

### Step 3: Run AuxGen (Heavy CPU Math)
Generate Paillier keys and Ring-Pedersen parameters. **This takes 5 to 15 minutes.**
```bash
./target/release/mpc-cli --config config/admin.toml aux-gen
```
*Monitor progress via `tail -f logs/node1.log`. Wait until all 3 nodes log "AuxInfo generated and saved successfully".*

### Step 4: Run DKG (Unified Multi-Chain Cold Vault)
Because Bitcoin, Ethereum, Tron, and XRP all use the **secp256k1** curve, a single DKG session generates a unified master keypair that controls vaults on all four chains simultaneously.
```bash
./target/release/mpc-cli --config config/admin.toml keygen \
  --curve secp256k1 \
  --threshold 2
```
*Monitor the node logs (`tail -f logs/node1.log`). The nodes will automatically calculate and print the Master Addresses for all supported chains:*
```text
🔑🔑🔑 MASTER ETHEREUM ADDRESS: 0x4072bc2d... 🔑🔑🔑
🔑🔑🔑 MASTER BITCOIN ADDRESS: 1A1zP1eP... 🔑🔑🔑
🔑🔑🔑 MASTER TRON ADDRESS: TJYy1b... 🔑🔑🔑
🔑🔑🔑 MASTER XRP ADDRESS: rHb9CJ... 🔑🔑🔑
```

### Step 5: Fund the Cold Master Vaults
Using the MPC addresses printed in the node logs, send funds directly to these Cold Vault addresses. **Do not use BIP32 child derivation for these vaults.** 

*(Note: Any transaction change from these vaults will be automatically routed to the API's Hot Wallet hierarchy defined by `MASTER_XPUB` in your `.env`.)*

### Step 6: Generate Solana Vaults (FROST DKG)
Because Solana uses the **Ed25519** curve, it requires its own separate FROST Distributed Key Generation session.
```bash
./target/release/mpc-cli --config config/admin.toml solana-keygen
```
*Monitor the node logs for `🔑🔑🔑 SOLANA VAULT GENERATED! Address: ... 🔑🔑🔑`.*

---

## Phase 3: Administrative Operations

*Note: Ensure `MPC_TOKEN` (scoped to `mpc-coordinator`) is exported in your terminal before running these.*

### Check Cluster Status
```bash
./target/release/mpc-cli --config config/admin.toml status
```

### Backup Key Shares
```bash
./target/release/mpc-cli --config config/admin.toml backup \
  --output-dir ./backups
```

### Key Rotation (Refresh) Strategy

> ⚠️ **CRITICAL LIMITATION**: Native cryptographic share rotation is **only supported for `n-of-n` vaults** (e.g., 3-of-3). If you attempt to run `rotate` on a threshold `t-of-n` vault (e.g., 2-of-3), the nodes will reject the request with a `TssProtocol` error. 

For threshold vaults, MPC-RS requires a **Migration Rotation** workflow to achieve forward secrecy. This is the industry-standard approach for threshold MPC systems:

**Step 1: Generate a New Vault**
Initiate a fresh DKG ceremony to create a new, mathematically distinct vault.
```bash
./target/release/mpc-cli --config config/admin.toml keygen --curve secp256k1 --threshold 2
```

**Step 2: Transfer Funds**
Use the MPC network to sign a standard transaction that sweeps **all funds** from the old vault's master address to the new vault's master address.

**Step 3: Decommission the Old Vault**
Once the transfer is confirmed on-chain, the old key shares are considered retired. You can securely delete the old `master` share from the nodes' HSMs to complete the rotation.

*(Note: If you are specifically running an `n-of-n` vault and wish to test the native `rotate` command, you may do so by passing the session ID of the `n-of-n` DKG as the `--key-id`.)*
```bash
./target/release/mpc-cli --config config/admin.toml rotate --key-id th15-w0u1d-b3-th3-k3y 
```

### Emergency Drain (Break-Glass)
The `drain` command triggers a multi-chain emergency withdrawal. 

**CRITICAL:** Because MPC-RS uses the "Vault per DKG" model, you **MUST** pass an empty derivation path (`""`) to sign with the raw Master Key. This ensures mathematical alignment with the Master Address you funded on the blockchain.

**Bitcoin Example:**
```bash
./target/release/mpc-cli --config config/admin.toml drain \
  --chain bitcoin \
  --from-address "<YOUR_MASTER_BTC_ADDRESS_FROM_LOGS>" \
  --target-address "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" \
  --derivation-path ""
```

**Ethereum Example:**
```bash
./target/release/mpc-cli --config config/admin.toml drain \
  --chain ethereum \
  --from-address "<YOUR_MASTER_ETH_ADDRESS_FROM_LOGS>" \
  --target-address "0xYourColdWalletAddress..." \
  --derivation-path ""
```

---

## Phase 4: Testing Multi-Chain Emergency Drain

### 1. Ethereum (Local via Anvil)

**Step 1: Start Anvil**
```bash
anvil
```

**Step 2: Update `.env` and Restart Coordinator**
```env
ETH_RPC_URL=http://127.0.0.1:8545
ETH_CHAIN_ID=31337
```

**Step 3: Fund the MPC Master Address**
```bash
# Send 1 ETH from Anvil's default rich account to your Master ETH Address (from node logs)
cast send <YOUR_MASTER_ETH_ADDRESS> --value 1ether --private-key 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

**Step 4: Execute the Drain**
```bash
./target/release/mpc-cli --config config/admin.toml drain \
  --chain ethereum \
  --from-address "<YOUR_MASTER_ETH_ADDRESS>" \
  --target-address "0x7fab7513feff0efa3d241e0be5365d5092685162" \
  --derivation-path ""
```

---

## Summary: Execution Order

| Step | Binary / Action              | Description                                    | Frequency                |
|------|------------------------------|------------------------------------------------|--------------------------|
| 1    | `./run-local.sh`             | Start Coordinator, Nodes, and API              | Once (persistent)        |
| 2    | `mpc-cli dev-token`          | Generate scope-bound Admin JWT                 | Daily / Per Session      |
| 3    | `mpc-cli aux-gen`            | Generate Paillier/RSA ZKP parameters           | **Once (Initial Setup)** |
| 4    | `mpc-cli keygen`             | Generate Unified Multi-Chain Cold Vault        | Once per Vault           |
| 5    | Fund Master Addresses        | Send funds to addresses in node logs           | Per Vault                |
| 6    | `mpc-cli solana-keygen`      | Generate Ed25519 FROST Solana Vaults           | On-Demand (Per Account)  |
| 7    | `mpc-cli status`             | Health check                                   | As needed                |
| 8    | `mpc-cli backup`             | Export encrypted shares                        | Periodic                 |
| 9    | `mpc-cli drain`              | Emergency break-glass (`--derivation-path ""`) | Never (hopefully)        |
