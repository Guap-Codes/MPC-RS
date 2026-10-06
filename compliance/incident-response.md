# Security Incident Response Procedures

**Document Version:** 1.0
**Classification:** INTERNAL / CONFIDENTIAL

## 1. Incident Classification
Incidents in the MPC-RS cluster are classified by severity:
*   **Sev-1 (Critical):** Suspected compromise of the Master Private Key, or compromise of $t$ (threshold) or more nodes.
*   **Sev-2 (High):** Compromise of a single node (below threshold), HSM hardware failure, or loss of network connectivity to a quorum.
*   **Sev-3 (Medium):** API Gateway degradation, failed DKG ceremonies, or policy engine misconfigurations.

## 2. Roles and Responsibilities
*   **Incident Commander (IC):** VP of Engineering or CISO. Authority to declare Sev-1 and trigger break-glass procedures.
*   **SecOps Lead:** Responsible for forensic analysis, log retrieval, and network isolation.
*   **Custody Committee:** Multi-sig approvers required to authorize emergency fund migrations.

## 3. Response Playbooks

### Playbook A: Single Node Compromise (Sev-2)
*Condition: One `mpc-node` server is breached, but the threshold ($t$) is not met.*
1.  **Isolate:** Sever the network connection to the compromised node via firewall rules.
2.  **Revoke:** Revoke the compromised node's mTLS certificate in the Root CA.
3.  **Migrate:** Because the attacker possesses one share, the vault is considered "warm". The Custody Committee must immediately initiate a **Migration Rotation** (generate a new vault and move funds).
4.  **Forensics:** Snapshot the compromised server's RAM and disk for malware analysis.

### Playbook B: Suspected Master Key Compromise (Sev-1)
*Condition: Attacker has bypassed the API and is actively signing unauthorized transactions, or $t$ nodes are compromised.*
1.  **Declare Sev-1:** Incident Commander declares a critical custody event.
2.  **Break-Glass Drain:** An authorized administrator executes the emergency drain command:
    ```bash
    export MPC_TOKEN=$(./target/release/mpc-cli dev-token)
    ./target/release/mpc-cli --config config/admin.toml drain \
      --chain bitcoin \
      --target-address "<PRE_CONFIGURED_COLD_STORAGE_ADDRESS>"
    ```
3.  **Halt Operations:** Shut down the `mpc-api` gateway to prevent further user deposits.
4.  **Notify:** Trigger legal and regulatory notification protocols (e.g., SOC 2 breach notification, customer communication).

### Playbook C: HSM Hardware Failure (Sev-2)
*Condition: A YubiHSM or CloudHSM instance becomes physically or logically unresponsive.*
1.  **Verify Quorum:** Ensure the remaining active nodes still meet the signing threshold. If yes, operations continue normally.
2.  **Provision Replacement:** Spin up a new `mpc-node` server and provision a new HSM.
3.  **Restore:** Use the `mpc-cli backup` artifacts to restore the encrypted key share into the new HSM.
4.  **Re-register:** Update the `mpc-coordinator` routing table to include the new node's mTLS certificate.

## 4. Post-Incident Review (PIR)
Within 48 hours of resolving any Sev-1 or Sev-2 incident, the SecOps Lead must publish a PIR document detailing:
*   Timeline of events (using `mpc-common` HMAC audit logs).
*   Root cause analysis.
*   Corrective and Preventive Actions (CAPA), including updates to `mpc-core` or `policy-engine` rules.
