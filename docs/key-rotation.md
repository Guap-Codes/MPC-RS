# Key Rotation Protocol Specification

Proactive key rotation is a critical security control that limits the exposure window of a compromised key share. MPC-RS supports **Zero-Downtime Proactive Key Refresh**.

## The Refresh Protocol
Unlike traditional wallets that require generating a new address and migrating funds, MPC-RS uses a cryptographic refresh protocol that updates the underlying secret shares **without changing the master public key or the blockchain addresses**.

### Mathematical Flow
Given current shares $x_i$ such that $\sum x_i = x$:
1. Nodes engage in a secure MPC protocol to generate random zero-sum masks $\Delta_i$ such that $\sum \Delta_i = 0$.
2. Each node updates its local share: $x_i' = x_i + \Delta_i$.
3. The new shares $x_i'$ still sum to the exact same master private key $x$.
4. The old shares $x_i$ are cryptographically zeroized and deleted from the HSM.

## Execution Flow
1. **Initiation:** The administrator runs `mpc-cli rotate`.
2. **Orchestration:** The Coordinator initiates a `Refresh` session across all $n$ nodes.
3. **Computation:** Nodes compute the zero-sum masks and update their HSM-encrypted shares.
4. **Verification:** Nodes verify the new shares against the existing master public key.
5. **Completion:** The old shares are permanently overwritten.

## Security Guarantees
- **Forward Secrecy:** If an attacker compromises $t$ nodes *before* a rotation, their stolen shares become mathematically useless immediately *after* the rotation.
- **Zero Downtime:** The master public key remains identical. No funds need to be moved, and no downstream systems need to be updated.
