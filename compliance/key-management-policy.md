# Key Management Policy

**Document Version:** 1.0
**Effective Date:** August 2026
**Applies to:** MPC-RS Infrastructure, DevOps, and Security Operations

## 1. Purpose
This policy defines the lifecycle management of cryptographic keys within the MPC-RS threshold signature infrastructure. It ensures that digital asset custody meets institutional security standards, preventing single points of failure and unauthorized fund movement.

## 2. Key Generation (Distributed Key Generation - DKG)
*   **Protocol:** All initial key generation MUST utilize the CGGMP21 protocol for secp256k1 curves or FROST for ed25519 curves.
*   **Quorum:** A minimum threshold of $t$ out of $n$ nodes must participate (e.g., 2-of-3 or 3-of-5).
*   **Entropy:** Randomness is sourced from the OS-level Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) via `OsRng`.
*   **Execution:** DKG is triggered exclusively via the `mpc-cli keygen` command by an authenticated administrator. The Master Public Key (XPub) is extracted and stored in the `mpc-api` database; private key shares never leave the nodes.

## 3. Key Storage and Protection
*   **Hardware Security Modules (HSM):** In production environments, all private key shares MUST be stored within FIPS 140-2 Level 3 certified HSMs (e.g., AWS CloudHSM, YubiHSM 2).
*   **Encryption at Rest:** Key shares are serialized using `postcard` and encrypted via the HSM's native AES-256-GCM wrapping mechanisms.
*   **Memory Safety:** The Rust `Zeroize` trait is strictly enforced on all memory structures holding key material to prevent core-dump leakage.
*   **SoftHSM Restriction:** The `SoftHsm` provider is strictly prohibited in production environments and is reserved for local development and CI testing.

## 4. Key Usage and Signing
*   **Policy Evaluation:** Before any signing session is initiated, the transaction payload MUST pass through the `policy-engine` to verify institutional rules (e.g., daily limits, whitelists).
*   **Threshold Signing:** Signing requires a live quorum of nodes. The `mpc-coordinator` orchestrates the session, but the cryptographic aggregation happens peer-to-peer via `mpc-protocol`.
*   **Identifiable Abort:** If a node behaves maliciously or fails to provide valid Zero-Knowledge Proofs (ZKPs) during signing, the protocol will abort and identify the faulty node.

## 5. Key Rotation and Refresh
*   **Proactive Refresh (n-of-n):** For non-threshold (n-of-n) vaults, administrators MUST execute `mpc-cli rotate` every 90 days. This updates the underlying key shares without altering the Master Public Key, mitigating long-term share exposure.
*   **Migration Rotation (t-of-n):** Because the CGGMP21 protocol does not currently support threshold refresh, t-of-n vaults MUST undergo a Migration Rotation. This involves generating a new vault via DKG and signing an internal transaction to move all funds to the new Master Public Key.

## 6. Backup and Disaster Recovery
*   **Encrypted Backups:** Administrators must periodically run `mpc-cli backup` to export HSM-wrapped key shares.
*   **Air-Gapped Storage:** Exported backups must be stored on offline, air-gapped media (e.g., encrypted USB drives in a physical safe).
*   **Shamir Secret Sharing (Optional):** For extreme security, the master HSM wrapping key can be split using Shamir's Secret Sharing among multiple geographic custodians.

## 7. Key Destruction
*   Upon decommissioning a vault, the `mpc-cli drain` command must be used to move funds to a cold storage address.
*   Following the drain, the HSM partitions containing the key shares must be cryptographically erased (zeroized) via the HSM management interface.
