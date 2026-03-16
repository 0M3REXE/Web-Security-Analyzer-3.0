# Web Security Analyzer – Rust Port

A fast, dependency-free CLI security scanner that analyses URLs using
heuristic checks and an optional ONNX ML model trained by the companion
Python script.

## Quick Start

### 1. (Optional) Export the ML model

Install Python dependencies and run the export script from the repository root:

```bash
pip install tensorflow tf2onnx scikit-learn numpy
python export_model.py
```

This produces:
- `web_security_analyzer/model.onnx`  – ONNX model for inference
- `web_security_analyzer/scaler.json` – StandardScaler parameters

> **Note:** If you skip this step the tool still works in *heuristics-only* mode
> (the ML prediction will be omitted from the output).

### 2. Build the Rust analyzer

```bash
cd web_security_analyzer
cargo build --release
```

### 3. Run

**Analyze a single URL:**
```bash
./target/release/web_security_analyzer --url https://example.com
```

**Analyze multiple URLs:**
```bash
./target/release/web_security_analyzer \
  --url https://google.com \
  --url http://evil-phish.xyz/login.php
```

**JSON output (great for scripting):**
```bash
./target/release/web_security_analyzer --url https://example.com --json
```

**Custom model / scaler paths:**
```bash
./target/release/web_security_analyzer \
  --model /path/to/model.onnx \
  --scaler /path/to/scaler.json \
  --url https://example.com
```

**Interactive mode** (no `--url` flag):
```bash
./target/release/web_security_analyzer
```

## Heuristic Checks

| Check | Description |
|---|---|
| `https` | Whether the URL uses HTTPS |
| `patterns` | Regex match against known malicious URL patterns |
| `tld` | Whether the TLD is in the high-risk list (`.xyz`, `.tk`, …) |
| `reputation` | Bonus for well-known reputable domains |
| `domain_length` | Unusually long domain names |
| `ip_url` | IP address used instead of a domain name |
| `owasp` | Keywords indicating common OWASP vulnerabilities |
| `redirect_chain` | Excessive or cross-domain HTTP redirects |
| `ssl` | SSL certificate validity |
| `html` | Suspicious inline scripts / content patterns |
| `domain_age` | WHOIS-based domain creation date |

## Risk Score

The final score blends heuristics (30%) and the ML prediction (70%) on a
0–10 scale:

| Score | Level |
|---|---|
| 0–3.9 | Low Risk |
| 4.0–6.9 | Medium Risk |
| 7.0–10 | High Risk |

## Running Tests

```bash
cargo test
```
