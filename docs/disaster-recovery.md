# Disaster Recovery & Break-Glass Procedures

This document outlines procedures for recovering from catastrophic failures and executing emergency break-glass operations.

## Scenario 1: Single Node Failure
- **Impact:** Minimal. MPC-RS operates on a $t$-of-$n$ threshold (e.g., 2-of-3).
- **Resolution:** The cluster continues to sign transactions using the remaining $t$ healthy nodes. The failed node should be reprovisioned and its shares restored from backup (see Scenario 3).

## Scenario 2: Total Cluster Loss (All Nodes Destroyed)
- **Impact:** Critical. Inability to sign new transactions.
- **Resolution:** 
  1. Provision new hardware and install `mpc-node`.
  2. Restore the HSM master keys from offline, air-gapped physical backups.
  3. Import the encrypted key share backups using `mpc-cli restore`.
  4. Re-establish mTLS certificates and restart the cluster.

## Scenario 3: Share Backup & Restoration
Administrators must periodically export encrypted share backups.
- **Export:** `mpc-cli backup --output-dir ./backups`
  - *Note: The exported shares are encrypted by the node's HSM. They can only be decrypted by a node possessing the corresponding HSM master key.*
- **Storage:** Backups must be stored in geographically distributed, physically secure locations (e.g., bank safe deposit boxes).

## Scenario 4: The Emergency Drain (Break-Glass)
If the MPC cluster is critically compromised, or if a catastrophic bug prevents normal API operations, administrators can execute an **Emergency Drain** to move all funds to a pre-configured, offline cold storage wallet.

### Execution
The `drain` command bypasses the standard API policy engine and directly orchestrates the nodes to sweep all funds.

```bash
# Authenticate with a highly privileged, break-glass JWT
export MPC_TOKEN=$(./target/release/mpc-cli dev-token --audience mpc-coordinator --scope break-glass)

# Execute the multi-chain drain
./target/release/mpc-cli --config config/admin.toml drain \
  --chain ethereum \
  --from-address "<MASTER_VAULT_ADDRESS>" \
  --target-address "<OFFLINE_COLD_STORAGE_ADDRESS>" \
  --derivation-path ""
```

### Post-Drain Protocol
1. The vault is now empty and considered burned.
2. A forensic audit must be conducted to determine the cause of the break-glass event.
3. A completely new DKG ceremony must be performed to generate a fresh set of master keys and addresses.
