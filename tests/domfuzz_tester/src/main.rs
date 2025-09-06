use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::collections::HashSet;

#[derive(Debug, Clone)]
struct Variation {
    score: String,
    domain: String,
    transformation: String,
    status: Option<String>,
}

fn find_domfuzz_binary() -> PathBuf {
    // Priority: DOMFUZZ_BIN env var
    if let Ok(path) = env::var("DOMFUZZ_BIN") {
        let p = PathBuf::from(path);
        if p.is_file() {
            return p;
        }
    }

    // Try common relative locations from this test app directory
    let candidates = [
        "../../target/release/domfuzz",
        "../../target/debug/domfuzz",
        "../target/release/domfuzz",
        "../target/debug/domfuzz",
        "./target/release/domfuzz",
        "./target/debug/domfuzz",
    ];

    for cand in candidates {
        let p = PathBuf::from(cand);
        if p.is_file() {
            return p;
        }
    }

    // Fall back to PATH lookup
    if let Ok(paths) = env::var("PATH") {
        for dir in paths.split(':') {
            let mut p = PathBuf::from(dir);
            p.push("domfuzz");
            if p.is_file() {
                return p;
            }
        }
    }

    panic!("Unable to locate domfuzz binary. Set DOMFUZZ_BIN env var to the path of ./target/release/domfuzz.");
}

fn run_domfuzz(args: &[&str]) -> (i32, String, String) {
    let bin = find_domfuzz_binary();

    let output = Command::new(bin)
        .args(args)
        .output()
        .expect("failed to execute domfuzz");

    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

fn parse_output(stdout: &str) -> Vec<Variation> {
    let mut out = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        // Expected formats:
        // "<score>, <domain>, <transformation>"
        // or with status checking: "<score>, <domain>, <transformation>, <status>"
        let parts: Vec<String> = line.split(',').map(|s| s.trim().to_string()).collect();
        if parts.len() >= 2 {
            // Be tolerant if implementation prints fewer columns
            let score = if parts.len() >= 1 { parts[0].clone() } else { String::new() };
            let domain = if parts.len() >= 2 { parts[1].clone() } else { String::new() };
            let transformation = if parts.len() >= 3 { parts[2].clone() } else { String::new() };
            let status = if parts.len() >= 4 { Some(parts[3].clone()) } else { None };
            out.push(Variation { score, domain, transformation, status });
        }
    }
    out
}

fn domain_part(fqdn: &str) -> &str {
    fqdn.split('.').next().unwrap_or(fqdn)
}

fn assert_contains_domain(variants: &[Variation], expected_domain: &str) -> Result<(), String> {
    if variants.iter().any(|v| v.domain == expected_domain) {
        Ok(())
    } else {
        Err(format!("Expected domain '{}' not found in output", expected_domain))
    }
}

fn assert_contains_transformation(variants: &[Variation], expected_transform: &str) -> Result<(), String> {
    if variants.iter().any(|v| v.transformation == expected_transform) {
        Ok(())
    } else {
        Err(format!("Expected transformation '{}' not found in output", expected_transform))
    }
}

fn assert_no_transformation(variants: &[Variation], not_expected_transform: &str) -> Result<(), String> {
    if variants.iter().any(|v| v.transformation == not_expected_transform) {
        Err(format!("Unexpected transformation '{}' present in output", not_expected_transform))
    } else {
        Ok(())
    }
}

fn unique_transformations(variants: &[Variation]) -> HashSet<String> {
    variants.iter().map(|v| v.transformation.clone()).collect()
}

fn assert_transform_subset(variants: &[Variation], allowed: &[&str]) -> Result<(), String> {
    let allowed: HashSet<String> = allowed.iter().map(|s| s.to_string()).collect();
    for tr in unique_transformations(variants) {
        if !tr.is_empty() && !allowed.contains(&tr) {
            return Err(format!("Unexpected transformation label: {}", tr));
        }
    }
    Ok(())
}

fn assert_len_limit(variants: &[Variation], limit: usize) -> Result<(), String> {
    if variants.len() <= limit { Ok(()) } else { Err(format!("Output length {} exceeded limit {}", variants.len(), limit)) }
}

fn assert_no_original(variants: &[Variation], original: &str) -> Result<(), String> {
    if variants.iter().any(|v| v.domain == original) {
        Err(format!("Original domain '{}' was included in output", original))
    } else { Ok(()) }
}

fn is_vowel(c: char) -> bool {
    matches!(c.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u')
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let m = a_chars.len();
    let n = b_chars.len();
    if m == 0 { return n; }
    if n == 0 { return m; }
    let mut dp = vec![vec![0usize; n + 1]; m + 1];
    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }
    for i in 1..=m {
        for j in 1..=n {
            let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
            dp[i][j] = std::cmp::min(
                std::cmp::min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                dp[i - 1][j - 1] + cost,
            );
            // Optional: transposition (Damerau)
            if i > 1 && j > 1 && a_chars[i - 1] == b_chars[j - 2] && a_chars[i - 2] == b_chars[j - 1] {
                dp[i][j] = std::cmp::min(dp[i][j], dp[i - 2][j - 2] + 1);
            }
        }
    }
    dp[m][n]
}

fn count_pos_diffs_same_len(a: &str, b: &str) -> usize {
    a.chars().zip(b.chars()).filter(|(x, y)| x != y).count()
}

fn assert_leetspeak_ratio_limit(variants: &[Variation], original: &str, max_ratio: f32) -> Result<(), String> {
    let orig = domain_part(original);
    for v in variants {
        if v.transformation == "1337speak" {
            let var_dom = domain_part(&v.domain);
            if var_dom.chars().count() != orig.chars().count() { continue; }
            let diffs = count_pos_diffs_same_len(orig, var_dom);
            let allowed = ((orig.chars().count() as f32) * max_ratio).ceil() as usize;
            if diffs > allowed {
                return Err(format!("1337speak exceeded ratio: diffs={} > allowed={} in {}", diffs, allowed, v.domain));
            }
        }
    }
    Ok(())
}

fn assert_mixed_encodings_unicode_only(variants: &[Variation], original: &str) -> Result<(), String> {
    let orig = domain_part(original);
    for v in variants {
        if v.transformation == "mixed-encodings" {
            let var_dom = domain_part(&v.domain);
            if var_dom.len() != orig.len() { continue; }
            for (oc, vc) in orig.chars().zip(var_dom.chars()) {
                if oc != vc {
                    if vc.is_ascii() {
                        return Err(format!("mixed-encodings used ASCII replacement at position for {} -> {} in {}", oc, vc, v.domain));
                    }
                }
            }
        }
    }
    Ok(())
}

// ====== Individual transformation tests ======
fn test_1337speak() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "1337speak", "test.com"]);
    let variants = parse_output(&stdout);
    assert_no_original(&variants, "test.com")?;
    assert_contains_domain(&variants, "t3st.com")?;   // e -> 3
    assert_contains_domain(&variants, "7est.com")?;   // t -> 7
    assert_contains_domain(&variants, "te5t.com")?;   // s -> 5
    // Double non-adjacent substitutions should be present
    assert_contains_domain(&variants, "7e5t.com")?;   // t->7 at pos0 and s->5 at pos2
    // Ratio limit: <= 40% substitutions
    assert_leetspeak_ratio_limit(&variants, "test.com", 0.4)?;
    Ok(())
}

fn test_misspelling() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "misspelling", "test.com"]);
    let variants = parse_output(&stdout);
    assert_no_original(&variants, "test.com")?;
    assert_contains_domain(&variants, "tset.com")?;   // transpose 'e' and 's'
    assert_contains_domain(&variants, "tst.com")?;    // delete 'e'
    assert_contains_domain(&variants, "atest.com")?;  // insert 'a' at pos 0
    // Vowel swap present (e -> i)
    assert_contains_domain(&variants, "tist.com")?;
    // Presence of at least one double-error variant (edit distance >= 2) on length>=4 input
    let orig = domain_part("test");
    let has_double = variants.iter().any(|v| v.transformation == "misspelling" && levenshtein(orig, domain_part(&v.domain)) >= 2);
    if !has_double {
        return Err("Expected at least one double-error misspelling variant".to_string());
    }
    Ok(())
}

fn test_fat_finger() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "fat-finger", "test.com"]);
    let variants = parse_output(&stdout);
    assert_no_original(&variants, "test.com")?;
    assert_contains_domain(&variants, "teest.com")?;  // repeat 'e'
    assert_contains_domain(&variants, "trst.com")?;   // substitute 'e' -> 'r' (adjacent on QWERTY)
    assert_contains_domain(&variants, "twest.com")?;  // insert_before 'e' -> 'w'
    // Presence of at least one double-error variant (edit distance >= 2)
    let orig = domain_part("test");
    let has_double = variants.iter().any(|v| v.transformation == "fat-finger" && levenshtein(orig, domain_part(&v.domain)) >= 2);
    if !has_double {
        return Err("Expected at least one double-error fat-finger variant".to_string());
    }
    Ok(())
}

fn test_mixed_encodings() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "mixed-encodings", "test.com"]);
    let variants = parse_output(&stdout);
    assert_no_original(&variants, "test.com")?;
    // Replace ASCII 'e' with Cyrillic small letter ie (U+0435)
    let expected = format!("t{}st.com", '\u{0435}');
    assert_contains_domain(&variants, &expected)?;
    // Length of the domain part should be preserved for mixed-encodings substitutions
    for v in &variants {
        if v.domain.ends_with(".com") { // all in this test
            if v.transformation == "mixed-encodings" {
                let orig_len = domain_part("test").chars().count();
                let var_len = domain_part(&v.domain).chars().count();
                if var_len != orig_len {
                    return Err(format!("Mixed-encodings changed length: {} vs {} in {}", var_len, orig_len, v.domain));
                }
            }
        }
    }
    // Unicode only replacements for changed positions
    assert_mixed_encodings_unicode_only(&variants, "test.com")?;

    // Double substitutions on a longer domain (both 'o' replaced with Cyrillic 'о')
    let (_code2, stdout2, _stderr2) = run_domfuzz(&["-t", "mixed-encodings", "google.com"]);
    let variants2 = parse_output(&stdout2);
    let cyr_o = '\u{043E}'; // Cyrillic small letter o
    let expected2 = format!("g{}{}gle.com", cyr_o, cyr_o);
    assert_contains_domain(&variants2, &expected2)?;
    Ok(())
}

// ====== Lookalike bundle tests ======
fn test_lookalike_bundle_core() -> Result<(), String> {
    // Explicit lookalike bundle
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "lookalike", "test.com"]);
    let variants = parse_output(&stdout);

    // Includes all four per man page
    assert_contains_transformation(&variants, "1337speak")?;
    assert_contains_transformation(&variants, "misspelling")?;
    assert_contains_transformation(&variants, "fat-finger")?;
    assert_contains_transformation(&variants, "mixed-encodings")?;

    // No unrelated transformations
    assert_no_transformation(&variants, "bitsquatting")?;

    // Transformation labels are only from the allowed set
    assert_transform_subset(&variants, &["1337speak","misspelling","fat-finger","mixed-encodings"]) ?;

    // Ensure not reporting combo in one-transformation mode
    assert_no_transformation(&variants, "combo")?;

    // Score should parse as float
    for v in &variants {
        if let Err(e) = v.score.parse::<f64>() { return Err(format!("Score not parseable: {} ({})", v.score, e)); }
    }

    Ok(())
}

fn test_default_is_lookalike_bundle() -> Result<(), String> {
    // No -t should imply lookalike bundle
    let (_code, stdout, _stderr) = run_domfuzz(&["test.com"]);
    let variants = parse_output(&stdout);
    assert_contains_transformation(&variants, "1337speak")?;
    assert_contains_transformation(&variants, "misspelling")?;
    assert_contains_transformation(&variants, "fat-finger")?;
    assert_contains_transformation(&variants, "mixed-encodings")?;
    assert_no_transformation(&variants, "bitsquatting")?;
    assert_transform_subset(&variants, &["1337speak","misspelling","fat-finger","mixed-encodings"]) ?;
    Ok(())
}

fn test_n_limit_enforced() -> Result<(), String> {
    // Limit outputs with -n
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "1337speak", "-n", "5", "test.com"]);
    let variants = parse_output(&stdout);
    // Should not exceed limit (might be fewer if fewer variants exist)
    assert_len_limit(&variants, 5)
}

fn test_lookalike_n_limit_enforced() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "lookalike", "-n", "7", "test.com"]);
    let variants = parse_output(&stdout);
    assert_len_limit(&variants, 7)
}

fn main() {
    // Basic environment check (optional): verify domfuzz binary exists
    let bin = find_domfuzz_binary();
    eprintln!("Using domfuzz binary: {}", bin.display());
    if !bin.is_file() {
        eprintln!("Binary not found. Set DOMFUZZ_BIN to path of domfuzz or build it with 'cargo build --release' at repo root.");
        std::process::exit(2);
    }

    // Run tests
    let mut failures: Vec<String> = Vec::new();

    let tests: Vec<(&str, fn() -> Result<(), String>)> = vec![
        ("1337speak", test_1337speak),
        ("misspelling", test_misspelling),
        ("fat-finger", test_fat_finger),
        ("mixed-encodings", test_mixed_encodings),
        ("lookalike bundle core", test_lookalike_bundle_core),
        ("default is lookalike bundle", test_default_is_lookalike_bundle),
        ("n limit enforced", test_n_limit_enforced),
        ("lookalike n limit enforced", test_lookalike_n_limit_enforced),
    ];

    for (name, f) in &tests {
        match f() {
            Ok(()) => println!("[PASS] {}", name),
            Err(err) => {
                println!("[FAIL] {} -> {}", name, err);
                failures.push(format!("{}: {}", name, err));
            }
        }
    }

    if failures.is_empty() {
        println!("\nAll tests passed");
        std::process::exit(0);
    } else {
        println!("\n{} test(s) failed:", failures.len());
        for f in &failures { println!(" - {}", f); }
        std::process::exit(1);
    }
}

