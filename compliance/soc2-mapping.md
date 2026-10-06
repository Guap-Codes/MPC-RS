# SOC 2 Type II Trust Services Criteria (TSC) Mapping

This document maps the architectural components and operational procedures of the `mpc-rs` platform to the AICPA SOC 2 Trust Services Criteria. This mapping serves as the foundational evidence matrix for external auditors.

## Security (Common Criteria - CC)

| Criteria | Description | MPC-RS Implementation | Evidence / Artifact |
| :--- | :--- | :--- | :--- |
| **CC6.1** | Logical and physical access controls | All inter-service communication requires mutual TLS (mTLS). API and Admin CLI access requires RS256 JWT authentication. | `auth` crate, `mpc-protocol` mTLS transport, `generate-certs.sh` |
| **CC6.3** | Role-based access and least privilege | The `policy-engine` crate evaluates institutional rules (limits, time-locks, approver lists) before any signing session is authorized. | `policy-engine` crate, `compliance/iso27001-controls.csv` |
| **CC6.6** | Security measures against threats outside system boundaries | The `mpc-api` gateway enforces strict rate-limiting and CORS policies. The Coordinator is air-gapped from the public internet. | `mpc-api/src/middleware/ratelimit.rs`, `docker-compose.yml` |
| **CC6.8** | Malicious software prevention | `cargo-deny` is integrated into the CI/CD pipeline to ban unauthorized git dependencies and audit known CVEs. | `deny.toml`, `scripts/audit.sh` |
| **CC7.2** | Monitoring and anomaly detection | All cryptographic operations emit structured logs via OpenTelemetry. The `mpc-common::audit` crate chains events with HMAC signatures to prevent tampering. | `mpc-common/src/audit.rs`, OpenTelemetry config |
| **CC8.1** | Change management | All code changes require peer review. Cryptographic primitives are isolated in `mpc-core` and subject to formal verification stubs (Kani/Creusot). | Git branch protection rules, `crates/mpc-core/src/verification/` |

## Availability (A)

| Criteria | Description | MPC-RS Implementation | Evidence / Artifact |
| :--- | :--- | :--- | :--- |
| **A1.2** | Recovery and continuity | The `mpc-cli backup` command allows administrators to securely export HSM-encrypted key shares to offline, air-gapped storage for disaster recovery. | `mpc-cli/src/commands/backup.rs`, `docs/disaster-recovery.md` |
| **A1.3** | Resilience and failover | The threshold architecture (e.g., 2-of-3) ensures that signing and address generation can continue even if one `mpc-node` experiences a hardware failure or network partition. | `tests/chaos/network_churn.rs` |

## Confidentiality (C)

| Criteria | Description | MPC-RS Implementation | Evidence / Artifact |
| :--- | :--- | :--- | :--- |
| **C1.1** | Confidential information identification | Master private keys are never constructed in memory. Only encrypted key shares (`EncryptedShare`) exist, bound to specific HSM identifiers. | `mpc-common/src/types.rs` (`Zeroize` implementations) |
| **C1.2** | Protection of confidential information | Private keys are encrypted at rest using AES-256-GCM inside Hardware Security Modules (YubiHSM, AWS CloudHSM). | `crates/hsm/` implementations |
