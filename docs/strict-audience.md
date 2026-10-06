In an institutional-grade MPC custody system, you must enforce strict audience (`aud`) validation to prevent **Cross-Service Token Replay Attacks**. 

If a token meant for the API Gateway (`aud: mpc-api`) could also be used to authenticate against the Coordinator (`aud: mpc-coordinator`), a compromised frontend application could bypass the API Gateway's policy engine and directly trigger `EmergencyDrain` or `KeyRefresh` commands against your core infrastructure.

Here are the two production-grade patterns to solve this, depending on who is making the request.

---

### Pattern 1: The Admin CLI (Scope-Bound Tokens)
For operators using the `mpc-cli` to manage the cluster, the CLI should explicitly mint tokens scoped to the specific service they intend to target. 

**The Fix:** Add an `--audience` flag to your `dev-token` command.

Update **`crates/mpc-cli/src/commands/dev_token.rs`** to accept the audience as an argument:

```rust
// crates/mpc-cli/src/commands/dev_token.rs
use anyhow::{Result, Context};
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use serde::{Serialize, Deserialize};
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    aud: String,        
    iss: String,        
    roles: Vec<String>,
    exp: usize,
    iat: usize,
}

// Assuming you use clap for your CLI arguments:
#[derive(clap::Args, Debug)]
pub struct DevTokenArgs {
    /// The target audience for the token (e.g., mpc-api or mpc-coordinator)
    #[arg(long, default_value = "mpc-coordinator")]
    pub audience: String,
}

pub fn execute(args: DevTokenArgs) -> Result<()> {
    let private_key = fs::read("config/private.pem")
        .context("Failed to read config/private.pem")?;
    let encoding_key = EncodingKey::from_rsa_pem(&private_key)?;
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    let claims = Claims {
        sub: "admin-cli".to_string(),
        aud: args.audience.clone(), // <--- Use the CLI flag
        iss: "mpc-rs".to_string(),       
        roles: vec!["admin".to_string()],
        iat: now,
        exp: now + 86400, 
    };
    
    let token = encode(&Header::new(Algorithm::RS256), &claims, &encoding_key)?;
    println!("{}", token);
    Ok(())
}
```

**How to use it in production:**
* To talk to the Coordinator: `export MPC_TOKEN=$(./mpc-cli dev-token --audience mpc-coordinator)`
* To talk to the API Gateway: `export MPC_API_TOKEN=$(./mpc-cli dev-token --audience mpc-api)`

*Note: You must revert the `.without_audience_validation()` in `mpc-api/src/main.rs` so it strictly enforces `aud: mpc-api`.*

---

### Pattern 2: End-User Applications (Token Exchange / Service Accounts)
When a real user (e.g., a mobile app or a web frontend) wants to deposit or withdraw funds, they **should never receive a token that can talk to your internal MPC cluster**. 

In a production enterprise architecture, you use the **Service Account / Token Exchange** pattern:

1. **The User authenticates to the API Gateway:** 
   The user logs in via your enterprise Identity Provider (Auth0, AWS Cognito, Okta). The API Gateway receives a standard OIDC JWT (e.g., `aud: mpc-api-frontend`).
2. **The API Gateway validates the User:** 
   The API Gateway checks the user's JWT, verifies their withdrawal limits in the Policy Engine, and builds the PSBT.
3. **The API Gateway mints an Internal Service Token:** 
   To talk to the Coordinator to request the threshold signature, the API Gateway acts as a **Service Account**. It uses its own internal RSA private key to mint a machine-to-machine JWT with `aud: mpc-coordinator` and `sub: api-gateway-service`.
4. **The Coordinator validates the Service Token:** 
   The Coordinator sees the request is coming from the trusted API Gateway and executes the signing session.

#### How to implement Pattern 2:
You would update the `CoordinatorClient` inside `mpc-api` to automatically inject a service-level JWT on every outbound gRPC call using a Tonic Interceptor:

```rust
// crates/mpc-api/src/handlers/mod.rs (Conceptual Tonic Interceptor)

use tonic::service::Interceptor;
use tonic::Request;

pub struct AuthInterceptor {
    token: String, // Pre-minted JWT with aud: mpc-coordinator
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, tonic::Status> {
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.token).parse().unwrap(),
        );
        Ok(request)
    }
}
```

### Summary of Production Security Posture
| Actor 		            | Token Audience (`aud`) | Allowed Actions 						                        |
| :------------------------ | :--------------------- | :----------------------------------------------------------- |
| **Frontend / Mobile App** | `mpc-api-frontend`     | Request addresses, request withdrawals (via API Gateway).    |
| **API Gateway** 	        | `mpc-coordinator`      | Request signing sessions, get status (via Tonic Interceptor).|
| **Admin CLI** 	        | `mpc-coordinator`      | DKG, AuxGen, Key Refresh, Emergency Drain. 		            |
| **Admin CLI** 	        | `mpc-api` 	         | Bypass policy engine for manual API testing. 		        |

By strictly enforcing these boundaries, you ensure that even if an attacker compromises a frontend user's session token, they cannot use it to trigger an `EmergencyDrain` directly against the Coordinator, because the Coordinator will reject the token with `InvalidAudience`.
