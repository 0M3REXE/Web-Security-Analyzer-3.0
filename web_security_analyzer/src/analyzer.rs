use crate::heuristics::{self, SUSPICIOUS_TLDS};
use crate::inference::{self, OnnxPredictor};
use crate::models::{AnalysisResult, ScalerParams};
use std::path::Path;
use url::Url;

pub struct Analyzer {
    predictor: Option<OnnxPredictor>,
    scaler: Option<ScalerParams>,
}

impl Analyzer {
    /// Create an Analyzer, optionally loading the ONNX model + scaler.
    pub fn new(model_path: Option<&Path>, scaler_path: Option<&Path>) -> Self {
        let predictor = model_path.and_then(|p| {
            if p.exists() {
                match OnnxPredictor::load(p) {
                    Ok(pred) => {
                        eprintln!("[info] ONNX model loaded from {}", p.display());
                        Some(pred)
                    }
                    Err(e) => {
                        eprintln!("[warn] Could not load ONNX model: {e}");
                        None
                    }
                }
            } else {
                eprintln!(
                    "[warn] Model file not found at {}. Run export_model.py first.",
                    p.display()
                );
                None
            }
        });

        let scaler = scaler_path.and_then(|p| {
            if p.exists() {
                match std::fs::read_to_string(p) {
                    Ok(content) => match serde_json::from_str::<ScalerParams>(&content) {
                        Ok(s) => {
                            eprintln!("[info] Scaler loaded from {}", p.display());
                            Some(s)
                        }
                        Err(e) => {
                            eprintln!("[warn] Could not parse scaler.json: {e}");
                            None
                        }
                    },
                    Err(e) => {
                        eprintln!("[warn] Could not read scaler.json: {e}");
                        None
                    }
                }
            } else {
                eprintln!(
                    "[warn] Scaler file not found at {}. Run export_model.py first.",
                    p.display()
                );
                None
            }
        });

        Self { predictor, scaler }
    }

    /// Analyse a single URL and return a fully populated `AnalysisResult`.
    pub fn analyze(&self, raw_url: &str) -> AnalysisResult {
        let url = normalise_url(raw_url);

        let parsed = Url::parse(&url).ok();
        let domain = parsed
            .as_ref()
            .and_then(|u| u.host_str())
            .unwrap_or("")
            .to_string();

        let tld = extract_tld(&domain);
        let base_domain = extract_base_domain(&domain);

        let mut results = AnalysisResult {
            url: url.clone(),
            domain: domain.clone(),
            ..Default::default()
        };

        // --- Synchronous heuristic checks ---
        heuristics::check_https(&url, &mut results);
        let pattern_count = heuristics::check_suspicious_patterns(&url, &mut results);
        heuristics::check_suspicious_tld(&tld, &mut results);
        heuristics::check_domain_reputation(&base_domain, &mut results);
        heuristics::check_domain_length(&domain, &mut results);
        heuristics::check_ip_url(&domain, &mut results);
        heuristics::check_owasp_vulnerabilities(&url, &mut results);

        // --- Network-dependent checks (may time-out) ---
        let redirect_count = heuristics::check_redirect_chain(&url, &mut results);
        heuristics::check_ssl_certificate(&domain, &mut results);
        heuristics::check_html_content(&url, &mut results);
        let domain_age_days = heuristics::check_domain_age(&domain, &mut results);

        // --- Compute heuristic average ---
        let scores: Vec<f64> = results.heuristic_scores.values().copied().collect();
        let heuristic_avg = if scores.is_empty() {
            0.0
        } else {
            scores.iter().sum::<f64>() / scores.len() as f64
        };
        results.heuristic_average = (heuristic_avg * 100.0).round() / 100.0;

        // --- ML prediction ---
        let ml_score = if let (Some(predictor), Some(scaler)) = (&self.predictor, &self.scaler) {
            let features = inference::extract_features(
                &url,
                pattern_count,
                &domain,
                &tld,
                domain_age_days,
                redirect_count,
                SUSPICIOUS_TLDS,
            );
            let raw = features.to_vec();
            let scaled = scaler.transform(&raw);
            match predictor.predict(&scaled) {
                Ok(pred) => {
                    results.ml_prediction = Some(pred);
                    if pred == 1 {
                        results.details.push(
                            "ML model flagged this URL as potentially malicious.".to_string(),
                        );
                        let importances = inference::feature_importances();
                        for (name, imp) in importances.iter().take(3) {
                            results.details.push(format!(
                                "Important factor: {} (importance: {imp:.2})",
                                name.replace('_', " ")
                            ));
                        }
                    }
                    if pred == 1 { 10.0 } else { 0.0 }
                }
                Err(e) => {
                    eprintln!("[warn] Inference error: {e}");
                    0.0
                }
            }
        } else {
            0.0
        };

        // --- Final blended score ---
        // When ML model is available: 30% heuristics + 70% ML prediction.
        // When no model: use the heuristic average directly as the risk score.
        let final_score = if results.ml_prediction.is_some() {
            0.3 * results.heuristic_average + 0.7 * ml_score
        } else {
            results.heuristic_average
        };
        results.risk_score = (final_score * 100.0).round() / 100.0;

        results.risk_level = if results.risk_score >= 7.0 {
            "High Risk".to_string()
        } else if results.risk_score >= 4.0 {
            "Medium Risk".to_string()
        } else {
            "Low Risk".to_string()
        };

        results
    }
}

// ---------------------------------------------------------------------------
// URL normalisation
// ---------------------------------------------------------------------------

fn normalise_url(url: &str) -> String {
    if url.starts_with("http://") || url.starts_with("https://") {
        url.to_string()
    } else {
        format!("http://{url}")
    }
}

// ---------------------------------------------------------------------------
// TLD / base-domain extraction (manual, no extra system deps required)
// ---------------------------------------------------------------------------

/// Extract the TLD from a host string, e.g. "sub.example.co.uk" → ".co.uk".
/// Falls back to the last label preceded by a dot.
fn extract_tld(domain: &str) -> String {
    // Strip port if present
    let host = domain.split(':').next().unwrap_or(domain);
    let parts: Vec<&str> = host.split('.').collect();
    match parts.len() {
        0 | 1 => String::new(),
        2 => format!(".{}", parts[1]),
        _ => {
            // Heuristic: if the second-to-last part is short (≤ 3 chars, e.g. "co"),
            // treat the last two as the TLD (e.g. ".co.uk").
            let n = parts.len();
            if parts[n - 2].len() <= 3 {
                format!(".{}.{}", parts[n - 2], parts[n - 1])
            } else {
                format!(".{}", parts[n - 1])
            }
        }
    }
}

/// Extract "domain.tld" from "sub.domain.tld".
fn extract_base_domain(domain: &str) -> String {
    let host = domain.split(':').next().unwrap_or(domain);
    let parts: Vec<&str> = host.split('.').collect();
    match parts.len() {
        0 => String::new(),
        1 => host.to_string(),
        2 => host.to_string(),
        _ => {
            let n = parts.len();
            // Same heuristic as extract_tld
            if parts[n - 2].len() <= 3 && n >= 3 {
                format!("{}.{}.{}", parts[n - 3], parts[n - 2], parts[n - 1])
            } else {
                format!("{}.{}", parts[n - 2], parts[n - 1])
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalise_adds_scheme() {
        assert_eq!(normalise_url("example.com"), "http://example.com");
        assert_eq!(
            normalise_url("https://example.com"),
            "https://example.com"
        );
    }

    #[test]
    fn tld_extraction() {
        assert_eq!(extract_tld("example.com"), ".com");
        assert_eq!(extract_tld("sub.example.co.uk"), ".co.uk");
        assert_eq!(extract_tld("evil.xyz"), ".xyz");
    }

    #[test]
    fn base_domain_extraction() {
        assert_eq!(extract_base_domain("example.com"), "example.com");
        assert_eq!(extract_base_domain("sub.example.com"), "example.com");
        assert_eq!(extract_base_domain("google.com"), "google.com");
    }
}
