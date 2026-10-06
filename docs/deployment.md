# Deployment & Infrastructure Guide

Deploying MPC-RS requires strict adherence to network segmentation and hardware security principles.

## 1. Infrastructure Requirements
- **MPC Nodes:** Should be deployed in physically and logically separated environments (e.g., different cloud providers, different AWS regions, or bare-metal data centers).
- **Coordinator & API:** Can be co-located but must sit behind a strict WAF and load balancer.
- **HSMs:** Production nodes **must** be backed by FIPS 140-2 Level 3 certified hardware (YubiHSM 2, AWS CloudHSM, Azure Managed HSM).

## 2. mTLS Certificate Authority
All inter-service communication is encrypted and authenticated via mutual TLS (mTLS). 
Generate the internal CA and node certificates using the provided script:
```bash
./scripts/generate-certs.sh
```
*Never expose the CA private key to the internet. Store it in an offline, air-gapped environment.*

## 3. Node Configuration & HSM Isolation
Each `mpc-node` dynamically isolates its state into a node-specific directory at runtime to prevent cross-node corruption.

Example `config/node1.toml`:
```toml
party_id = 1
listen_addr = "0.0.0.0:50001"

[tls]
certificate_path = "config/node1-cert.pem"
private_key_path = "config/node1-key.pem"
ca_certificate_path = "config/ca-cert.pem"

[hsm]
provider = "YubiHSM" # or "SoftHsm" for dev
share_label = "master"

[hsm.soft_hsm]
data_dir = "./data/node1"
```

## 4. Environment Variables
The Coordinator and API Gateway rely on the `.env` file for external integrations:
```env
# Database
DATABASE_URL=sqlite://./mpc_wallet.db

# Node Registry
NODE_1_URL="https://10.0.1.10:50001"
NODE_1_DOMAIN="node1.mpc.internal"

# Blockchain RPCs
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
MEMPOOL_API_URL=https://mempool.space/api
```

## 5. Docker & Kubernetes
For production, use the provided `Dockerfile` to build immutable container images. Deploy using Kubernetes with `NetworkPolicies` that strictly deny all ingress to the MPC Nodes except from the Coordinator's specific IP/CIDR.

