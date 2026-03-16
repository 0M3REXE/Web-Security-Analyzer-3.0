use std::collections::HashMap;

/// All security check scores and metadata for a single URL analysis.
#[derive(Debug, Default)]
pub struct AnalysisResult {
    pub url: String,
    pub domain: String,
    /// Individual heuristic check scores (0–10 each, negative = bonus).
    pub heuristic_scores: HashMap<String, f64>,
    /// Average of all heuristic scores (0–10).
    pub heuristic_average: f64,
    /// Final blended risk score (0–10).
    pub risk_score: f64,
    /// "Low Risk" / "Medium Risk" / "High Risk"
    pub risk_level: String,
    /// Human-readable detail messages.
    pub details: Vec<String>,
    /// Optional ML model output: Some(1) = malicious, Some(0) = benign, None = no model.
    pub ml_prediction: Option<i32>,
}

/// The 9-dimensional feature vector fed to the ONNX model.
#[derive(Debug, Default, Clone)]
pub struct Features {
    pub uses_https: f32,
    pub suspicious_patterns_count: f32,
    pub domain_age_days: f32,
    pub uses_suspicious_tld: f32,
    pub domain_length: f32,
    pub uses_ip: f32,
    pub redirects: f32,
    pub subdomains_count: f32,
    pub url_length: f32,
}

impl Features {
    pub fn to_vec(&self) -> Vec<f32> {
        vec![
            self.uses_https,
            self.suspicious_patterns_count,
            self.domain_age_days,
            self.uses_suspicious_tld,
            self.domain_length,
            self.uses_ip,
            self.redirects,
            self.subdomains_count,
            self.url_length,
        ]
    }
}

/// StandardScaler parameters loaded from `scaler.json`.
#[derive(Debug, serde::Deserialize)]
pub struct ScalerParams {
    pub mean: Vec<f32>,
    pub std: Vec<f32>,
}

impl ScalerParams {
    /// Transform a raw feature vector using mean/std normalisation.
    pub fn transform(&self, features: &[f32]) -> Vec<f32> {
        features
            .iter()
            .enumerate()
            .map(|(i, &v)| {
                let mean = self.mean.get(i).copied().unwrap_or(0.0);
                let std = self.std.get(i).copied().unwrap_or(1.0);
                if std.abs() < f32::EPSILON {
                    0.0
                } else {
                    (v - mean) / std
                }
            })
            .collect()
    }
}
