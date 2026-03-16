mod analyzer;
mod heuristics;
mod inference;
mod models;

use analyzer::Analyzer;
use clap::Parser;
use colored::*;
use std::path::PathBuf;

/// Web Security Analyzer – Rust port of the Python ML-based URL scanner.
#[derive(Parser, Debug)]
#[command(
    name = "web_security_analyzer",
    version,
    about = "Analyze URLs for security risks using heuristics and an optional ONNX ML model",
    long_about = None
)]
struct Cli {
    /// One or more URLs to analyze (if omitted, enters interactive mode)
    #[arg(short, long, num_args = 0..)]
    url: Vec<String>,

    /// Path to the ONNX model file
    #[arg(long, default_value = "model.onnx")]
    model: PathBuf,

    /// Path to the scaler JSON file
    #[arg(long, default_value = "scaler.json")]
    scaler: PathBuf,

    /// Output results as JSON
    #[arg(long)]
    json: bool,
}

fn main() {
    let cli = Cli::parse();

    // Build the analyzer (loads model + scaler if they exist)
    let analyzer = Analyzer::new(Some(&cli.model), Some(&cli.scaler));

    if cli.url.is_empty() {
        interactive_mode(&analyzer, cli.json);
    } else {
        for url in &cli.url {
            let result = analyzer.analyze(url);
            if cli.json {
                print_json(&result);
            } else {
                print_results(&result);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Interactive mode
// ---------------------------------------------------------------------------

fn interactive_mode(analyzer: &Analyzer, json: bool) {
    use std::io::{self, BufRead, Write};

    loop {
        println!();
        println!("{}", "Options:".bold().cyan());
        println!("  1. Analyze a URL");
        println!("  2. Exit");
        print!("\nEnter your choice (1-2): ");
        io::stdout().flush().unwrap();

        let stdin = io::stdin();
        let line = stdin.lock().lines().next();
        let choice = match line {
            Some(Ok(l)) => l.trim().to_string(),
            _ => break,
        };

        match choice.as_str() {
            "1" => {
                print!("\nEnter a URL to analyze: ");
                io::stdout().flush().unwrap();
                let stdin2 = io::stdin();
                if let Some(Ok(url)) = stdin2.lock().lines().next() {
                    let url = url.trim().to_string();
                    if !url.is_empty() {
                        let result = analyzer.analyze(&url);
                        if json {
                            print_json(&result);
                        } else {
                            print_results(&result);
                        }
                    }
                }
            }
            "2" => {
                println!("\nExiting. Thank you for using Web Security Analyzer!");
                break;
            }
            _ => {
                println!("{}", "Invalid choice. Please enter 1 or 2.".red());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Pretty-print output
// ---------------------------------------------------------------------------

fn print_results(result: &models::AnalysisResult) {
    let divider = "═".repeat(50);
    println!("\n{}", divider.magenta().bold());
    println!(
        "{} {}",
        "ANALYSIS RESULTS FOR:".bold(),
        result.url.cyan()
    );
    println!("{}", divider.magenta().bold());

    let risk_score_str = format!("{:.2}/10", result.risk_score);
    let colored_score = match result.risk_level.as_str() {
        "High Risk" => risk_score_str.red().bold(),
        "Medium Risk" => risk_score_str.yellow().bold(),
        _ => risk_score_str.green().bold(),
    };
    println!("  {:<22} {colored_score}", "RISK SCORE:".bold());

    let level_colored = match result.risk_level.as_str() {
        "High Risk" => result.risk_level.red().bold(),
        "Medium Risk" => result.risk_level.yellow().bold(),
        _ => result.risk_level.green().bold(),
    };
    println!("  {:<22} {level_colored}", "RISK LEVEL:".bold());

    println!(
        "  {:<22} {:.2}",
        "HEURISTIC AVERAGE:".bold(),
        result.heuristic_average
    );

    if let Some(pred) = result.ml_prediction {
        let pred_str = if pred == 1 {
            "Malicious".red().bold()
        } else {
            "Benign".green().bold()
        };
        println!("  {:<22} {pred_str}", "ML PREDICTION:".bold());
    } else {
        println!(
            "  {:<22} {}",
            "ML PREDICTION:".bold(),
            "(no model – heuristics only)".dimmed()
        );
    }

    println!();
    println!("{}", "  HEURISTIC SCORES:".bold());
    let mut scores: Vec<(&String, &f64)> = result.heuristic_scores.iter().collect();
    scores.sort_by_key(|(k, _)| k.as_str());
    for (check, score) in &scores {
        let bar = score_bar(**score);
        println!("    {:<20} {:>5.1}  {}", check, score, bar);
    }

    println!();
    println!("{}", "  DETAILS:".bold());
    if result.details.is_empty() {
        println!("    • No specific security issues detected.");
    } else {
        for detail in &result.details {
            println!("    • {detail}");
        }
    }

    println!("{}\n", divider.magenta().bold());
}

fn score_bar(score: f64) -> String {
    let clamped = score.clamp(0.0, 10.0) as usize;
    let filled = "█".repeat(clamped);
    let empty = "░".repeat(10usize.saturating_sub(clamped));
    let bar = format!("{filled}{empty}");
    if clamped >= 7 {
        bar.red().to_string()
    } else if clamped >= 4 {
        bar.yellow().to_string()
    } else {
        bar.green().to_string()
    }
}

// ---------------------------------------------------------------------------
// JSON output
// ---------------------------------------------------------------------------

fn print_json(result: &models::AnalysisResult) {
    let obj = serde_json::json!({
        "url": result.url,
        "domain": result.domain,
        "risk_score": result.risk_score,
        "risk_level": result.risk_level,
        "heuristic_average": result.heuristic_average,
        "heuristic_scores": result.heuristic_scores,
        "ml_prediction": result.ml_prediction,
        "details": result.details,
    });
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}
