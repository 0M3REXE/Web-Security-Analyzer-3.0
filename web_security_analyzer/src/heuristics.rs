use crate::models::AnalysisResult;
use regex::Regex;
use scraper::{Html, Selector};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

const SUSPICIOUS_PATTERNS: &[&str] = &[
    r"login.*\.php",
    r"secure.*\.php",
    r"account.*\.php",
    r"admin.*\.php",
    r"bank.*\.php",
    r"update.*\.php",
    r"wp-includes",
    r"download.*\.php",
    r"\.exe$",
    r"(bitcoin|btc|crypto|wallet|blockchain)",
    r"(free.*money|prize|winner)",
    r"password.*reset",
];

const MALICIOUS_HTML_PATTERNS: &[(&str, &str)] = &[
    (r"(?i)<script>.*eval\(.*\)</script>", "eval() usage in inline script"),
    (r"(?i)<script>.*document\.write\(.*\)</script>", "document.write() usage in inline script"),
    (r"(?i)<!--\s*malicious\s*-->", "malicious comment marker"),
];

pub const SUSPICIOUS_TLDS: &[&str] = &[
    ".xyz", ".top", ".club", ".online", ".site", ".tk", ".ml", ".ga", ".cf",
];

const REPUTABLE_DOMAINS: &[&str] = &[
    "google.com",
    "facebook.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "github.com",
    "youtube.com",
];

const OWASP_KEYWORDS: &[(&str, &[&str])] = &[
    (
        "injection",
        &["select", "drop", "insert", "update", "' or", "\" or"],
    ),
    ("xss", &["<script>", "javascript:"]),
    ("sensitive_data_exposure", &["password", "ssn", "creditcard"]),
    ("security_misconfiguration", &[".env", "config"]),
];

// ---------------------------------------------------------------------------
// HTTPS check
// ---------------------------------------------------------------------------

pub fn check_https(url: &str, results: &mut AnalysisResult) {
    let score = if url.starts_with("https://") { 0.0 } else { 10.0 };
    results.heuristic_scores.insert("https".to_string(), score);
    if score > 0.0 {
        results
            .details
            .push("Website does not use HTTPS encryption.".to_string());
    }
}

// ---------------------------------------------------------------------------
// Suspicious patterns check
// ---------------------------------------------------------------------------

pub fn check_suspicious_patterns(
    url: &str,
    results: &mut AnalysisResult,
) -> usize {
    let mut matches = 0usize;
    for pat in SUSPICIOUS_PATTERNS {
        if let Ok(re) = Regex::new(pat) {
            if re.is_match(url) {
                matches += 1;
            }
        }
    }

    let mut score = ((matches * 3) as f64).min(10.0);
    let subdomain_count = url.matches('.').count().saturating_sub(1);
    if subdomain_count > 3 {
        score = (score + 2.0).min(10.0);
        results.details.push(format!(
            "URL contains excessive subdomains ({subdomain_count})."
        ));
    }
    if url.len() > 100 {
        score = (score + 2.0).min(10.0);
        results.details.push(format!(
            "Unusually long URL ({} characters).",
            url.len()
        ));
    }

    results
        .heuristic_scores
        .insert("patterns".to_string(), score);
    matches
}

// ---------------------------------------------------------------------------
// Suspicious TLD check
// ---------------------------------------------------------------------------

pub fn check_suspicious_tld(tld: &str, results: &mut AnalysisResult) {
    let score = if SUSPICIOUS_TLDS.contains(&tld) {
        10.0
    } else {
        0.0
    };
    results.heuristic_scores.insert("tld".to_string(), score);
    if score > 0.0 {
        results
            .details
            .push(format!("Domain uses suspicious TLD: {tld}."));
    }
}

// ---------------------------------------------------------------------------
// Domain reputation check
// ---------------------------------------------------------------------------

pub fn check_domain_reputation(base_domain: &str, results: &mut AnalysisResult) {
    let score = if REPUTABLE_DOMAINS.contains(&base_domain) {
        -10.0
    } else {
        0.0
    };
    results
        .heuristic_scores
        .insert("reputation".to_string(), score);
    if score < 0.0 {
        results
            .details
            .push("Domain has good reputation.".to_string());
    }
}

// ---------------------------------------------------------------------------
// Domain length check
// ---------------------------------------------------------------------------

pub fn check_domain_length(domain: &str, results: &mut AnalysisResult) {
    let score = if domain.len() > 30 { 10.0 } else { 0.0 };
    results
        .heuristic_scores
        .insert("domain_length".to_string(), score);
    if score > 0.0 {
        results.details.push(format!(
            "Unusually long domain name ({} characters).",
            domain.len()
        ));
    }
}

// ---------------------------------------------------------------------------
// IP-based URL check
// ---------------------------------------------------------------------------

pub fn check_ip_url(domain: &str, results: &mut AnalysisResult) {
    let is_ip = is_ipv4(domain);
    let score = if is_ip { 10.0 } else { 0.0 };
    results
        .heuristic_scores
        .insert("ip_url".to_string(), score);
    if is_ip {
        results
            .details
            .push("URL uses an IP address instead of a domain name.".to_string());
    }
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| p.parse::<u8>().is_ok())
}

// ---------------------------------------------------------------------------
// OWASP keywords check
// ---------------------------------------------------------------------------

pub fn check_owasp_vulnerabilities(url: &str, results: &mut AnalysisResult) {
    let url_lower = url.to_lowercase();
    let mut score = 0.0_f64;

    for (vuln, keywords) in OWASP_KEYWORDS {
        for keyword in *keywords {
            if url_lower.contains(keyword) {
                score += 5.0;
                results.details.push(format!(
                    "URL may be prone to {vuln} vulnerability (found: {keyword})."
                ));
                break;
            }
        }
    }

    // Simulate OWASP API call
    if url_lower.contains("admin") {
        score += 5.0;
    }

    results
        .heuristic_scores
        .insert("owasp".to_string(), score.min(10.0));
}

// ---------------------------------------------------------------------------
// Redirect chain check  (blocking HTTP)
// ---------------------------------------------------------------------------

pub fn check_redirect_chain(url: &str, results: &mut AnalysisResult) -> usize {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::limited(10))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    match client.get(url).send() {
        Ok(resp) => {
            // reqwest counts each redirect as a response in the redirect chain,
            // but exposes it via Response::url() (final URL) and the redirect history.
            // The number of redirects is not directly exposed, so we compare URLs.
            let final_url = resp.url().to_string();
            let chain_length: usize = if final_url != url { 1 } else { 0 };

            let mut score = ((chain_length * 2) as f64).min(10.0);

            if let Ok(parsed_final) = url::Url::parse(&final_url) {
                let final_domain = parsed_final.host_str().unwrap_or("");
                if !url.contains(final_domain) {
                    score = (score + 2.0).min(10.0);
                    results.details.push(format!(
                        "Final redirect domain ({final_domain}) differs from original."
                    ));
                }
            }

            results
                .details
                .push(format!("Redirect chain length: {chain_length}."));
            results
                .heuristic_scores
                .insert("redirect_chain".to_string(), score);
            chain_length
        }
        Err(_) => {
            results
                .heuristic_scores
                .insert("redirect_chain".to_string(), 5.0);
            results
                .details
                .push("Unable to fully follow redirect chain.".to_string());
            0
        }
    }
}

// ---------------------------------------------------------------------------
// SSL certificate check (blocking TCP)
// ---------------------------------------------------------------------------

pub fn check_ssl_certificate(domain: &str, results: &mut AnalysisResult) {
    // We use reqwest to do a HEAD to port 443 and check whether it succeeds.
    let url = format!("https://{domain}");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    match client.head(&url).send() {
        Ok(_) => {
            results
                .heuristic_scores
                .insert("ssl".to_string(), 0.0);
            results
                .details
                .push("SSL certificate is valid.".to_string());
        }
        Err(e) if e.is_connect() || e.to_string().contains("certificate") => {
            results
                .heuristic_scores
                .insert("ssl".to_string(), 10.0);
            results
                .details
                .push("SSL certificate is invalid or expired.".to_string());
        }
        Err(_) => {
            results
                .heuristic_scores
                .insert("ssl".to_string(), 10.0);
            results
                .details
                .push("Unable to verify SSL certificate.".to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// HTML content check (blocking HTTP)
// ---------------------------------------------------------------------------

pub fn check_html_content(url: &str, results: &mut AnalysisResult) {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap_or_default();

    match client.get(url).send() {
        Ok(resp) => match resp.text() {
            Ok(body) => {
                let mut score = 0.0_f64;
                for (pat, description) in MALICIOUS_HTML_PATTERNS {
                    if let Ok(re) = Regex::new(pat) {
                        if re.is_match(&body) {
                            score += 3.0;
                            results
                                .details
                                .push(format!("Suspicious HTML/JS pattern detected: {description}"));
                        }
                    }
                }
                // Check for suspicious inline scripts via scraper
                let document = Html::parse_document(&body);
                if let Ok(sel) = Selector::parse("script") {
                    for node in document.select(&sel) {
                        let text = node.inner_html();
                        if text.contains("eval(") || text.contains("document.write(") {
                            score = (score + 2.0).min(10.0);
                            results
                                .details
                                .push("Suspicious inline script (eval/document.write) detected.".to_string());
                            break;
                        }
                    }
                }
                results
                    .heuristic_scores
                    .insert("html".to_string(), score.min(10.0));
            }
            Err(_) => {
                results.heuristic_scores.insert("html".to_string(), 5.0);
                results
                    .details
                    .push("Unable to decode HTML content.".to_string());
            }
        },
        Err(_) => {
            results.heuristic_scores.insert("html".to_string(), 5.0);
            results
                .details
                .push("Unable to fetch or analyze HTML content.".to_string());
        }
    }
}

// ---------------------------------------------------------------------------
// Domain age via WHOIS (raw TCP query)
// ---------------------------------------------------------------------------

/// Query WHOIS for the given domain and return a best-effort domain age in days.
/// Returns `None` if the lookup fails or the date cannot be parsed.
pub fn whois_domain_age_days(domain: &str) -> Option<i64> {
    // Use the IANA root WHOIS server first; most TLDs are accessible there.
    let whois_server = "whois.iana.org";
    let response = whois_query(domain, whois_server)?;

    // Many registries embed a "refer:" line pointing to the authoritative WHOIS server.
    let authoritative = parse_refer(&response);
    let final_response = if let Some(ref server) = authoritative {
        whois_query(domain, server).unwrap_or(response)
    } else {
        response
    };

    parse_creation_date(&final_response)
}

fn whois_query(domain: &str, server: &str) -> Option<String> {
    let addr = format!("{server}:43");
    let mut stream = TcpStream::connect_timeout(
        &addr.parse().ok()?,
        Duration::from_secs(5),
    )
    .ok()?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok()?;
    stream
        .write_all(format!("{domain}\r\n").as_bytes())
        .ok()?;

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break,
            Ok(_) => response.push_str(&line),
            Err(_) => break,
        }
    }
    if response.is_empty() {
        None
    } else {
        Some(response)
    }
}

fn parse_refer(whois_response: &str) -> Option<String> {
    for line in whois_response.lines() {
        let lower = line.to_lowercase();
        if lower.starts_with("refer:") {
            return Some(line[6..].trim().to_string());
        }
    }
    None
}

fn parse_creation_date(whois_response: &str) -> Option<i64> {
    use chrono::{DateTime, NaiveDate, TimeZone, Utc};

    // Common WHOIS date field names
    let field_prefixes = [
        "creation date:",
        "created:",
        "registered on:",
        "domain registered:",
        "registration time:",
        "registered:",
    ];

    for line in whois_response.lines() {
        let lower = line.to_lowercase();
        for prefix in &field_prefixes {
            if lower.starts_with(prefix) {
                let raw = line[prefix.len()..].trim();
                // Try RFC3339 / ISO 8601 first
                if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
                    let age = (Utc::now() - dt.with_timezone(&Utc)).num_days();
                    return Some(age);
                }
                // Try "YYYY-MM-DD"
                if let Ok(nd) = NaiveDate::parse_from_str(raw, "%Y-%m-%d") {
                    let dt = Utc.from_utc_datetime(&nd.and_hms_opt(0, 0, 0)?);
                    let age = (Utc::now() - dt).num_days();
                    return Some(age);
                }
                // Try "DD-Mon-YYYY"
                if let Ok(nd) = NaiveDate::parse_from_str(raw, "%d-%b-%Y") {
                    let dt = Utc.from_utc_datetime(&nd.and_hms_opt(0, 0, 0)?);
                    let age = (Utc::now() - dt).num_days();
                    return Some(age);
                }
            }
        }
    }
    None
}

pub fn check_domain_age(domain: &str, results: &mut AnalysisResult) -> f32 {
    match whois_domain_age_days(domain) {
        Some(age) if age < 30 => {
            results.heuristic_scores.insert("domain_age".to_string(), 10.0);
            results.details.push(format!(
                "Domain is very new ({age} days old)."
            ));
            age as f32
        }
        Some(age) if age < 90 => {
            results.heuristic_scores.insert("domain_age".to_string(), 5.0);
            results.details.push(format!(
                "Domain is relatively new ({age} days old)."
            ));
            age as f32
        }
        Some(age) => {
            results.heuristic_scores.insert("domain_age".to_string(), 0.0);
            age as f32
        }
        None => {
            results.heuristic_scores.insert("domain_age".to_string(), 5.0);
            results
                .details
                .push("Unable to determine domain age.".to_string());
            // Use median domain age as a neutral fallback for the feature vector
            365.0
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AnalysisResult;

    fn empty_result() -> AnalysisResult {
        AnalysisResult {
            url: "http://example.com".to_string(),
            domain: "example.com".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn https_check_secure() {
        let mut r = empty_result();
        check_https("https://example.com", &mut r);
        assert_eq!(r.heuristic_scores["https"], 0.0);
        assert!(r.details.is_empty());
    }

    #[test]
    fn https_check_insecure() {
        let mut r = empty_result();
        check_https("http://example.com", &mut r);
        assert_eq!(r.heuristic_scores["https"], 10.0);
        assert_eq!(r.details.len(), 1);
    }

    #[test]
    fn suspicious_tld_detected() {
        let mut r = empty_result();
        check_suspicious_tld(".xyz", &mut r);
        assert_eq!(r.heuristic_scores["tld"], 10.0);
    }

    #[test]
    fn safe_tld_ok() {
        let mut r = empty_result();
        check_suspicious_tld(".com", &mut r);
        assert_eq!(r.heuristic_scores["tld"], 0.0);
    }

    #[test]
    fn reputable_domain_gives_bonus() {
        let mut r = empty_result();
        check_domain_reputation("google.com", &mut r);
        assert!(r.heuristic_scores["reputation"] < 0.0);
    }

    #[test]
    fn ip_url_detected() {
        let mut r = empty_result();
        check_ip_url("192.168.1.1", &mut r);
        assert_eq!(r.heuristic_scores["ip_url"], 10.0);
    }

    #[test]
    fn domain_url_not_flagged_as_ip() {
        let mut r = empty_result();
        check_ip_url("example.com", &mut r);
        assert_eq!(r.heuristic_scores["ip_url"], 0.0);
    }

    #[test]
    fn long_domain_flagged() {
        let mut r = empty_result();
        check_domain_length("averylongdomainnamethatshouldgetflagged.com", &mut r);
        assert_eq!(r.heuristic_scores["domain_length"], 10.0);
    }

    #[test]
    fn owasp_sql_injection_detected() {
        let mut r = empty_result();
        check_owasp_vulnerabilities("http://site.com/page?id=1 drop table", &mut r);
        assert!(r.heuristic_scores["owasp"] > 0.0);
    }
}
