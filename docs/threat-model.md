# Threat Model (STRIDE Analysis)

This document outlines the security posture of MPC-RS against the STRIDE threat model.

## 1. Spoofing
- **Threat:** An attacker impersonates an MPC node or the API Gateway to inject malicious messages.
- **Mitigation:** **mTLS Everywhere.** Every gRPC connection requires a valid certificate signed by the internal CA. Certificate pinning is enforced.
- **Mitigation:** **Scope-Bound JWTs.** API requests require JWTs with strict `aud` (audience) claims. A token minted for `mpc-api` cannot be used to authenticate against `mpc-coordinator`.

## 2. Tampering
- **Threat:** An attacker modifies the transaction payload or MPC protocol messages in transit.
- **Mitigation:** **Signed Envelopes.** All P2P MPC protocol messages are wrapped in a `SignedEnvelope` containing an Ed25519 signature over the payload, session ID, and sender/receiver indices.
- **Mitigation:** **Blockchain Adapters.** The sighash is computed locally by the adapter and verified cryptographically by the nodes.

## 3. Repudiation
- **Threat:** A rogue insider signs a fraudulent transaction and denies involvement.
- **Mitigation:** **HMAC-Signed Audit Logs.** Every cryptographic operation, DKG session, and signing request is logged to an append-only, HMAC-chained audit trail.
- **Mitigation:** **Identifiable Abort.** The CGGMP21 protocol mathematically identifies which specific node(s) caused a signing failure or attempted a malicious ZKP.

## 4. Information Disclosure
- **Threat:** An attacker breaches a node's filesystem and steals the private key shares.
- **Mitigation:** **HSM Encryption at Rest.** Key shares are never written to disk in plaintext. They are encrypted by the HSM (YubiHSM/CloudHSM) using an AES-256 master key that never leaves the hardware boundary.
- **Mitigation:** **Secure Memory.** Shares are decrypted into RAM only for the duration of the signing session and zeroized immediately after.

## 5. Denial of Service (DoS)
- **Threat:** An attacker floods the API with signing requests, exhausting node CPU.
- **Mitigation:** **Rate Limiting.** The API Gateway enforces strict IP and JWT-based rate limits via `tower-governor`.
- **Mitigation:** **Identifiable Abort.** If a node is overwhelmed or malicious, the protocol aborts cleanly without hanging the entire cluster.

## 6. Elevation of Privilege
- **Threat:** An attacker compromises the API Gateway and attempts to trigger administrative DKG or Key Refresh operations.
- **Mitigation:** **Network Segmentation.** The API Gateway has no network route to the administrative CLI ports. Administrative operations (`mpc-cli`) require physical access or a separate, heavily restricted bastion host.
