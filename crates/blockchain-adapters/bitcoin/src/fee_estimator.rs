//! # Bitcoin Fee Estimation
//!
//! This module provides implementations of the [`FeeEstimator`](adapter_core::traits::FeeEstimator) 
//! trait for Bitcoin, allowing the system to dynamically query network conditions and calculate 
//! appropriate transaction fees in satoshis before building a transaction.

use adapter_core::traits::FeeEstimator;
use adapter_core::error::AdapterError;
use async_trait::async_trait;

/// A fee estimator that queries a Mempool.space-compatible API.
///
/// This estimator fetches real-time fee recommendations and multiplies the recommended 
/// "halfHourFee" rate (which typically ensures confirmation within ~1-2 blocks) by the 
/// transaction's virtual size (vsize) to calculate the total fee in satoshis.
pub struct MempoolFeeEstimator {
    client: reqwest::Client,
    api_base_url: String,
}

impl MempoolFeeEstimator {
    /// Creates a new `MempoolFeeEstimator` with a configured, timeout-protected HTTP client.
    ///
    /// # Arguments
    ///
    /// * `api_base_url` - The base URL of the Mempool API. For production, this is typically 
    ///   `"https://mempool.space/api"`. For local testing (e.g., with Nigiri), this would be 
    ///   `"http://127.0.0.1:3000/api"`.
    ///
    /// # Example
    ///
    /// ```rust
    /// // use bitcoin_adapter::fee_estimator::MempoolFeeEstimator;
    /// let estimator = MempoolFeeEstimator::new("https://mempool.space/api".to_string());
    /// ```
    #[must_use]
    pub fn new(api_base_url: String) -> Self {
        Self {
            // Add a strict timeout to prevent hanging requests and resource exhaustion in production
            client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(10))
                .build()
                .unwrap_or_default(),
            api_base_url,
        }
    }
}

#[async_trait]
impl FeeEstimator for MempoolFeeEstimator {
    /// Estimates the total transaction fee in satoshis based on the transaction's virtual size.
    ///
    /// # Arguments
    ///
    /// * `vsize` - The estimated virtual size of the transaction in virtual bytes (vBytes).
    ///
    /// # Returns
    ///
    /// The total estimated fee in satoshis (`sat_per_vbyte * vsize`).
    ///
    /// # Errors
    ///
    /// Returns an [`AdapterError::Internal`] if:
    /// - The HTTP request to the fee API times out (after 10 seconds) or encounters a network error.
    /// - The API returns a non-200 HTTP status code.
    /// - The API response cannot be parsed as valid JSON.
    ///
    /// # Note on Fallback Behavior
    ///
    /// If the API response is malformed, incomplete, or missing the `"halfHourFee"` field, 
    /// this method gracefully falls back to a conservative default of `10 sat/vB`. This ensures 
    /// the transaction can still be constructed and signed by the MPC nodes, albeit potentially 
    /// with a suboptimal fee rate, rather than failing the entire withdrawal request.
    async fn estimate_fee_sats(&self, vsize: usize) -> Result<u64, AdapterError> {
        let url = format!("{}/v1/fees/recommended", self.api_base_url);
        
        let response = self.client.get(&url).send().await
            .map_err(|e| AdapterError::Internal(format!("Fee API request failed: {e}")))?;
        
        if !response.status().is_success() {
            return Err(AdapterError::Internal(format!("Fee API returned status: {}", response.status())));
        }

        let fees: serde_json::Value = response.json().await
            .map_err(|e| AdapterError::Internal(format!("Fee API parse failed: {e}")))?;
        
        // Fallback to 10 sat/vB if the API response is malformed or missing the field
        let sat_per_vbyte = fees.get("halfHourFee").and_then(serde_json::Value::as_u64).unwrap_or(10); 
        
        // Safe conversion and arithmetic to satisfy clippy::as_conversions and arithmetic_side_effects
        let vsize_u64 = u64::try_from(vsize).unwrap_or(0);
        Ok(sat_per_vbyte.saturating_mul(vsize_u64))
    }
}



