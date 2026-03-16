use crate::models::Features;
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tract_onnx::prelude::*;

/// ONNX-backed ML predictor using pure-Rust `tract-onnx`.
pub struct OnnxPredictor {
    model: Arc<TypedSimplePlan>,
}

impl OnnxPredictor {
    /// Load the ONNX model from `model_path`.
    pub fn load(model_path: &Path) -> Result<Self> {
        let model = tract_onnx::onnx()
            .model_for_path(model_path)?
            .with_input_fact(0, f32::fact([1usize, 9].as_ref()).into())?
            .into_optimized()?
            .into_runnable()?;
        Ok(Self { model })
    }

    /// Run inference on a pre-scaled feature vector.
    /// Returns 1 (malicious) or 0 (benign).
    pub fn predict(&self, scaled_features: &[f32]) -> Result<i32> {
        let input: Tensor =
            tract_ndarray::Array2::from_shape_vec((1, scaled_features.len()), scaled_features.to_vec())?.into();

        let result = self.model.run(tvec!(input.into()))?;
        let prob = result[0]
            .to_array_view::<f32>()?
            .iter()
            .next()
            .copied()
            .unwrap_or(0.0);

        Ok(if prob >= 0.5 { 1 } else { 0 })
    }
}

/// Return the feature importances (fixed values matching the Python version).
pub fn feature_importances() -> Vec<(&'static str, f64)> {
    vec![
        ("uses_https", 0.15),
        ("suspicious_patterns_count", 0.20),
        ("domain_age_days", 0.10),
        ("uses_suspicious_tld", 0.15),
        ("domain_length", 0.10),
        ("uses_ip", 0.05),
        ("redirects", 0.10),
        ("subdomains_count", 0.05),
        ("url_length", 0.10),
    ]
}

/// Build the feature vector that is fed to the model.
pub fn extract_features(
    url: &str,
    suspicious_patterns_count: usize,
    domain: &str,
    tld: &str,
    domain_age_days: f32,
    redirects: usize,
    suspicious_tlds: &[&str],
) -> Features {
    let uses_https = if url.starts_with("https://") { 1.0 } else { 0.0 };
    let uses_suspicious_tld = if suspicious_tlds.contains(&tld) { 1.0 } else { 0.0 };
    let uses_ip = if is_ip_address(domain) { 1.0 } else { 0.0 };
    let subdomain_count = count_subdomains(domain) as f32;

    Features {
        uses_https,
        suspicious_patterns_count: suspicious_patterns_count as f32,
        domain_age_days,
        uses_suspicious_tld,
        domain_length: domain.len() as f32,
        uses_ip,
        redirects: redirects as f32,
        subdomains_count: subdomain_count,
        url_length: url.len() as f32,
    }
}

fn is_ip_address(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

fn count_subdomains(domain: &str) -> usize {
    let dots = domain.matches('.').count();
    if dots >= 2 { dots - 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ip_address() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(!is_ip_address("example.com"));
    }

    #[test]
    fn test_count_subdomains() {
        assert_eq!(count_subdomains("example.com"), 0);
        assert_eq!(count_subdomains("sub.example.com"), 1);
        assert_eq!(count_subdomains("a.b.example.com"), 2);
    }
}
