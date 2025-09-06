use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

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
        if parts.len() >= 3 {
            out.push(Variation {
                score: parts[0].clone(),
                domain: parts[1].clone(),
                transformation: parts[2].clone(),
                status: if parts.len() >= 4 { Some(parts[3].clone()) } else { None },
            });
        }
    }
    out
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

fn test_1337speak() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "1337speak", "test.com"]);
    let variants = parse_output(&stdout);
    assert_contains_domain(&variants, "t3st.com")?;   // e -> 3
    assert_contains_domain(&variants, "7est.com")?;   // t -> 7
    assert_contains_domain(&variants, "te5t.com")?;   // s -> 5
    Ok(())
}

fn test_misspelling() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "misspelling", "test.com"]);
    let variants = parse_output(&stdout);
    assert_contains_domain(&variants, "tset.com")?;   // transpose 'e' and 's'
    assert_contains_domain(&variants, "tst.com")?;    // delete 'e'
    assert_contains_domain(&variants, "atest.com")?;  // insert 'a' at pos 0
    Ok(())
}

fn test_fat_finger() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "fat-finger", "test.com"]);
    let variants = parse_output(&stdout);
    assert_contains_domain(&variants, "teest.com")?;  // repeat 'e'
    assert_contains_domain(&variants, "trst.com")?;   // substitute 'e' -> 'r' (adjacent on QWERTY)
    assert_contains_domain(&variants, "twest.com")?;  // insert_before 'e' -> 'w'
    Ok(())
}

fn test_mixed_encodings() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "mixed-encodings", "test.com"]);
    let variants = parse_output(&stdout);
    // Replace ASCII 'e' with Cyrillic small letter ie (U+0435)
    let expected = format!("t{}st.com", '\u{0435}');
    assert_contains_domain(&variants, &expected)?;
    Ok(())
}

fn test_lookalike_bundle() -> Result<(), String> {
    // Explicit bundle
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "lookalike", "test.com"]);
    let variants = parse_output(&stdout);

    // Should include at least one from each bundle member used by this codebase
    assert_contains_transformation(&variants, "1337speak")?;
    assert_contains_transformation(&variants, "misspelling")?;
    assert_contains_transformation(&variants, "fat-finger")?;
    assert_contains_transformation(&variants, "mixed-encodings")?;

    // Also test default (no -t) expands lookalike
    let (_code2, stdout2, _stderr2) = run_domfuzz(&["test.com"]);
    let variants2 = parse_output(&stdout2);
    assert_contains_transformation(&variants2, "1337speak")?;
    assert_contains_transformation(&variants2, "misspelling")?;
    assert_contains_transformation(&variants2, "fat-finger")?;
    assert_contains_transformation(&variants2, "mixed-encodings")?;

    Ok(())
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
        ("lookalike bundle", test_lookalike_bundle),
    ];

    for (name, f) in &tests {
        match f() {
            Ok(()) => {
                println!("[PASS] {}", name);
            }
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
        for f in &failures {
            println!(" - {}", f);
        }
        std::process::exit(1);
    }
}

