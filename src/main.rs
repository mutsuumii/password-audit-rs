use clap::Parser;
use sha1::{Sha1, Digest};
use std::fs;

#[derive(Parser)]
#[command(name = "password-audit", about = "Password strength auditor")]
struct Args {
    /// Password to audit
    password: Option<String>,

    /// File with passwords (one per line)
    #[arg(short, long)]
    file: Option<String>,
}

fn entropy(pw: &str) -> f64 {
    let mut charset = 0u32;
    if pw.chars().any(|c| c.is_ascii_lowercase()) { charset += 26; }
    if pw.chars().any(|c| c.is_ascii_uppercase()) { charset += 26; }
    if pw.chars().any(|c| c.is_ascii_digit()) { charset += 10; }
    if pw.chars().any(|c| !c.is_alphanumeric()) { charset += 33; }
    if charset == 0 { return 0.0; }
    pw.len() as f64 * (charset as f64).log2()
}

fn check_patterns(pw: &str) -> Vec<String> {
    let mut issues = Vec::new();
    let lower = pw.to_lowercase();

    if pw.len() < 8 { issues.push("Length < 8".into()); }
    if pw.len() < 12 { issues.push("Recommended: 12+ chars".into()); }
    if pw.chars().all(|c| c.is_ascii_lowercase()) { issues.push("Lowercase only".into()); }
    if pw.chars().all(|c| c.is_ascii_digit()) { issues.push("Digits only".into()); }

    // Repeated chars
    let bytes = pw.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i] == bytes[i+1] && bytes[i+1] == bytes[i+2] {
            issues.push("Repeated characters (aaa, 111...)".into());
            break;
        }
    }

    let weak = ["qwerty", "12345", "abcdef", "password", "admin", "letmein", "welcome"];
    for seq in weak {
        if lower.contains(seq) {
            issues.push(format!("Contains common sequence: {}", seq));
        }
    }
    issues
}

fn hibp_prefix(pw: &str) -> String {
    let hash = hex::encode(Sha1::digest(pw.as_bytes())).to_uppercase();
    format!("Prefix: {}, Suffix: {}", &hash[..5], &hash[5..])
}

fn audit(pw: &str) {
    let ent = entropy(pw);
    let issues = check_patterns(pw);
    let strength = if ent >= 60.0 && issues.is_empty() { "STRONG" }
        else if ent >= 40.0 { "MEDIUM" }
        else { "WEAK" };

    println!("\n{}", "=".repeat(50));
    println!("Password: {}", "*".repeat(pw.len()));
    println!("Length:   {}", pw.len());
    println!("Entropy:  {:.2} bits", ent);
    println!("Strength: {}", strength);
    if !issues.is_empty() {
        println!("Issues:");
        for i in &issues { println!("  - {}", i); }
    }
    println!("HIBP:     {}", hibp_prefix(pw));
}

fn main() {
    let args = Args::parse();
    if let Some(file) = args.file {
        let content = fs::read_to_string(&file).expect("Cannot read file");
        for line in content.lines() {
            let pw = line.trim();
            if !pw.is_empty() { audit(pw); }
        }
    } else if let Some(pw) = args.password {
        audit(&pw);
    } else {
        println!("Enter password:");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        audit(input.trim());
    }
}
