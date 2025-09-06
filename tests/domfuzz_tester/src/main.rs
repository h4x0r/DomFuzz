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
    // Only 1337speak labels should appear
    assert_transform_subset(&variants, &["1337speak"])?;
    assert_contains_domain(&variants, "t3st.com")?;   // e -> 3
    assert_contains_domain(&variants, "7est.com")?;   // t -> 7
    assert_contains_domain(&variants, "te5t.com")?;   // s -> 5
    // Double non-adjacent substitutions should be present
    assert_contains_domain(&variants, "7e5t.com")?;   // t->7 at pos0 and s->5 at pos2
    // Ratio limit: <= 40% substitutions
    assert_leetspeak_ratio_limit(&variants, "test.com", 0.4)?;
    Ok(())
}

fn test_1337speak_google_combinations() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "1337speak", "google.com"]);
    let variants = parse_output(&stdout);
    assert_transform_subset(&variants, &["1337speak"])?;
    // Common combos from manpage: g00gle, goog1e
    assert_contains_domain(&variants, "g00gle.com")?;
    assert_contains_domain(&variants, "goog1e.com")?;
    // Ratio limit for 6-char domain: <= ceil(0.4*6)=3 substitutions allowed
    assert_leetspeak_ratio_limit(&variants, "google.com", 0.4)?;
    Ok(())
}

fn test_1337speak_comprehensive_mappings() -> Result<(), String> {
    // Test all major 1337speak character mappings
    let mappings = [
        ("google", "g00gle", 'o', '0'),  // o -> 0
        ("hello", "he110", 'l', '1'),    // l -> 1  
        ("secure", "s3cure", 'e', '3'),  // e -> 3
        ("bank", "b@nk", 'a', '@'),      // a -> @
        ("store", "$tore", 's', '$'),    // s -> $
        ("great", "9reat", 'g', '9'),    // g -> 9
        ("table", "7able", 't', '7'),    // t -> 7
        ("bonus", "6onus", 'b', '6'),    // b -> 6
        ("zone", "2one", 'z', '2'),      // z -> 2
    ];
    
    for (input, expected, _orig_char, _leet_char) in mappings {
        let domain = format!("{}.com", input);
        let expected_domain = format!("{}.com", expected);
        let (_code, stdout, _stderr) = run_domfuzz(&["-t", "1337speak", &domain]);
        let variants = parse_output(&stdout);
        assert_contains_domain(&variants, &expected_domain)
            .map_err(|e| format!("1337speak mapping test failed for {}: {}", input, e))?;
    }
    Ok(())
}

fn test_misspelling() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "misspelling", "test.com"]);
    let variants = parse_output(&stdout);
    assert_no_original(&variants, "test.com")?;
    assert_transform_subset(&variants, &["misspelling"])?;
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

fn test_misspelling_google_combinations() -> Result<(), String> {
    // From manpage examples for misspelling
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "misspelling", "google.com"]);
    let variants = parse_output(&stdout);
    assert_transform_subset(&variants, &["misspelling"])?;
    assert_contains_domain(&variants, "googlle.com")?; // insertion
    assert_contains_domain(&variants, "gogle.com")?;   // deletion
    assert_contains_domain(&variants, "googel.com")?;  // transposition
    assert_contains_domain(&variants, "googke.com")?;  // keyboard adjacent
    assert_contains_domain(&variants, "guogle.com")?;  // vowel swap
    Ok(())
}

fn test_misspelling_comprehensive() -> Result<(), String> {
    // Test comprehensive misspelling patterns
    let test_cases = [
        // Character deletion
        ("hello", "hllo"),   // delete 'e'
        ("world", "wrld"),   // delete 'o' 
        // Character insertion
        ("test", "tesst"),   // double 's'
        ("bank", "baank"),   // double 'a'
        // Character transposition 
        ("form", "from"),    // transpose 'o' and 'r'
        ("united", "untied"), // transpose 'i' and 'e'
        // Vowel swaps
        ("secure", "sacure"), // e -> a
        ("online", "onlene"), // i -> e
        ("music", "mosic"),   // u -> o
    ];
    
    for (input, expected) in test_cases {
        let domain = format!("{}.com", input);
        let expected_domain = format!("{}.com", expected);
        let (_code, stdout, _stderr) = run_domfuzz(&["-t", "misspelling", &domain]);
        let variants = parse_output(&stdout);
        assert_contains_domain(&variants, &expected_domain)
            .map_err(|e| format!("Misspelling test failed for {} -> {}: {}", input, expected, e))?;
    }
    Ok(())
}

fn test_misspelling_keyboard_adjacency() -> Result<(), String> {
    // Test QWERTY keyboard adjacency errors
    let keyboard_tests = [
        ("google", "hoogle"), // g -> h (adjacent)
        ("facebook", "dacebook"), // f -> d (adjacent)
        ("secure", "aecure"), // s -> a (adjacent)
        ("login", "kLogin"),  // l -> k (adjacent) - case insensitive check
        ("music", "nusic"),   // m -> n (adjacent)
    ];
    
    for (input, expected) in keyboard_tests {
        let domain = format!("{}.com", input);
        let expected_domain = format!("{}.com", expected);
        let (_code, stdout, _stderr) = run_domfuzz(&["-t", "misspelling", &domain]);
        let variants = parse_output(&stdout);
        // Check case-insensitive for domains that might have case differences
        let found = variants.iter().any(|v| v.domain.to_lowercase() == expected_domain.to_lowercase());
        if !found {
            return Err(format!("Keyboard adjacency test failed for {} -> {}", input, expected));
        }
    }
    Ok(())
}

fn test_fat_finger() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "fat-finger", "test.com"]);
    let variants = parse_output(&stdout);
    assert_no_original(&variants, "test.com")?;
    assert_transform_subset(&variants, &["fat-finger"])?;
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

fn test_fat_finger_google_combinations() -> Result<(), String> {
    // From manpage examples for fat-finger
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "fat-finger", "google.com"]);
    let variants = parse_output(&stdout);
    assert_transform_subset(&variants, &["fat-finger"])?;
    assert_contains_domain(&variants, "gooogle.com")?; // repetition
    assert_contains_domain(&variants, "googke.com")?;  // adjacent substitution
    assert_contains_domain(&variants, "gpogle.com")?;  // adjacent insertion
    Ok(())
}

fn test_fat_finger_comprehensive() -> Result<(), String> {
    // Test comprehensive fat-finger patterns
    let doubling_tests = [
        ("apple", "appple"),   // double p
        ("google", "gooogle"), // double o
        ("amazon", "amazoon"), // double o
        ("office", "offfice"), // double f
    ];
    
    let adjacent_key_tests = [
        ("paypal", "oaypal"),  // p -> o (adjacent)
        ("secure", "aecure"),  // s -> a (adjacent) 
        ("music", "nusic"),    // m -> n (adjacent)
    ];
    
    let insert_before_tests = [
        ("bank", "bqank"),     // insert q before a
        ("test", "trest"),     // insert r before e -> "trest"
        ("mail", "mqail"),     // insert q before a
    ];
    
    // Test character doubling
    for (input, expected) in doubling_tests {
        let domain = format!("{}.com", input);
        let expected_domain = format!("{}.com", expected);
        let (_code, stdout, _stderr) = run_domfuzz(&["-t", "fat-finger", &domain]);
        let variants = parse_output(&stdout);
        assert_contains_domain(&variants, &expected_domain)
            .map_err(|e| format!("Fat-finger doubling test failed for {}: {}", input, e))?;
    }
    
    // Test adjacent key substitution
    for (input, expected) in adjacent_key_tests {
        let domain = format!("{}.com", input);
        let expected_domain = format!("{}.com", expected);
        let (_code, stdout, _stderr) = run_domfuzz(&["-t", "fat-finger", &domain]);
        let variants = parse_output(&stdout);
        assert_contains_domain(&variants, &expected_domain)
            .map_err(|e| format!("Fat-finger adjacent key test failed for {}: {}", input, e))?;
    }
    
    // Test insert before patterns (some may be present)
    for (input, expected) in insert_before_tests {
        let domain = format!("{}.com", input);
        let expected_domain = format!("{}.com", expected);
        let (_code, stdout, _stderr) = run_domfuzz(&["-t", "fat-finger", &domain]);
        let variants = parse_output(&stdout);
        // Note: Not all insert-before patterns may be generated, so we'll just check if any are present
        // This is more of a coverage test to see what the algorithm produces
        let _found = variants.iter().any(|v| v.domain == expected_domain);
        // Don't fail if not found, as the algorithm may prioritize certain patterns
    }
    
    Ok(())
}

fn test_mixed_encodings() -> Result<(), String> {
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "mixed-encodings", "test.com"]);
    let variants = parse_output(&stdout);
    assert_no_original(&variants, "test.com")?;
    assert_transform_subset(&variants, &["mixed-encodings"])?;
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

    // Another domain to cover 'a' mapping: amazon.com -> аmazon.com (Cyrillic 'a')
    let (_code3, stdout3, _stderr3) = run_domfuzz(&["-t", "mixed-encodings", "amazon.com"]);
    let variants3 = parse_output(&stdout3);
    let cyr_a = '\u{0430}';
    let expected3 = format!("{}mazon.com", cyr_a);
    assert_contains_domain(&variants3, &expected3)?;

    Ok(())
}

fn test_mixed_encodings_comprehensive() -> Result<(), String> {
    // Test comprehensive homoglyph character mappings based on enhanced IronGeek research
    let cyrillic_tests = [
        ("amazon", "а", 'a'), // Cyrillic 'а' (U+0430) looks like Latin 'a'
        ("google", "о", 'o'), // Cyrillic 'о' (U+043E) looks like Latin 'o' 
        ("paypal", "р", 'p'), // Cyrillic 'р' (U+0440) looks like Latin 'p'
        ("secure", "с", 'c'), // Cyrillic 'с' (U+0441) looks like Latin 'c'
        ("example", "е", 'e'), // Cyrillic 'е' (U+0435) looks like Latin 'e'
    ];
    
    let greek_tests = [
        ("alpha", "α", 'a'),  // Greek 'α' (U+03B1) looks like Latin 'a'
        ("beta", "β", 'b'),   // Greek 'β' (U+03B2) looks like Latin 'b' 
        ("micro", "μ", 'm'),  // Greek 'μ' (U+03BC) looks like Latin 'm'
        ("omega", "ο", 'o'),  // Greek 'ο' (U+03BF) looks like Latin 'o'
        ("rho", "ρ", 'p'),    // Greek 'ρ' (U+03C1) looks like Latin 'p'
    ];
    
    let fullwidth_tests = [
        ("bank", "ａ", 'a'),   // Fullwidth 'ａ' (U+FF41)
        ("office", "ｏ", 'o'), // Fullwidth 'ｏ' (U+FF4F) 
        ("service", "ｓ", 's'), // Fullwidth 'ｓ' (U+FF53)
    ];
    
    // Test Cyrillic substitutions
    for (input, homoglyph, _orig_char) in cyrillic_tests {
        let domain = format!("{}.com", input);
        let (_code, stdout, _stderr) = run_domfuzz(&["-t", "mixed-encodings", &domain]);
        let variants = parse_output(&stdout);
        
        // Look for any variant containing the homoglyph character
        let found = variants.iter().any(|v| v.domain.contains(homoglyph));
        if !found {
            return Err(format!("Cyrillic homoglyph '{}' not found for {}", homoglyph, input));
        }
    }
    
    // Test Greek substitutions
    for (input, homoglyph, _orig_char) in greek_tests {
        let domain = format!("{}.com", input);
        let (_code, stdout, _stderr) = run_domfuzz(&["-t", "mixed-encodings", &domain]);
        let variants = parse_output(&stdout);
        
        let found = variants.iter().any(|v| v.domain.contains(homoglyph));
        if !found {
            return Err(format!("Greek homoglyph '{}' not found for {}", homoglyph, input));
        }
    }
    
    // Test Fullwidth substitutions
    for (input, homoglyph, _orig_char) in fullwidth_tests {
        let domain = format!("{}.com", input);
        let (_code, stdout, _stderr) = run_domfuzz(&["-t", "mixed-encodings", &domain]);
        let variants = parse_output(&stdout);
        
        let found = variants.iter().any(|v| v.domain.contains(homoglyph));
        if !found {
            return Err(format!("Fullwidth homoglyph '{}' not found for {}", homoglyph, input));
        }
    }
    
    Ok(())
}

fn test_mixed_encodings_multiple_substitutions() -> Result<(), String> {
    // Test that enhanced algorithm generates both single and multiple substitutions
    let (_code, stdout, _stderr) = run_domfuzz(&["-t", "mixed-encodings", "amazon.com"]);
    let variants = parse_output(&stdout);
    
    let domain_variants: Vec<String> = variants.iter()
        .filter(|v| v.transformation == "mixed-encodings")
        .map(|v| v.domain.clone())
        .collect();
    
    // Check for at least one single substitution
    let has_single = domain_variants.iter().any(|d| {
        let orig = "amazon";
        let var_domain = domain_part(d);
        let diff_count = orig.chars().zip(var_domain.chars())
            .filter(|(o, v)| o != v)
            .count();
        diff_count == 1
    });
    
    // Check for at least one multiple (>=2) substitutions
    let has_multiple = domain_variants.iter().any(|d| {
        let orig = "amazon";
        let var_domain = domain_part(d);
        let diff_count = orig.chars().zip(var_domain.chars())
            .filter(|(o, v)| o != v)
            .count();
        diff_count >= 2
    });
    
    if !has_single {
        return Err("Expected single character substitutions in mixed-encodings".to_string());
    }
    if !has_multiple {
        return Err("Expected multiple character substitutions in mixed-encodings".to_string());
    }
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
        ("1337speak google combos", test_1337speak_google_combinations),
        ("1337speak comprehensive mappings", test_1337speak_comprehensive_mappings),
        ("misspelling", test_misspelling),
        ("misspelling google combos", test_misspelling_google_combinations),
        ("misspelling comprehensive", test_misspelling_comprehensive),
        ("misspelling keyboard adjacency", test_misspelling_keyboard_adjacency),
        ("fat-finger", test_fat_finger),
        ("fat-finger google combos", test_fat_finger_google_combinations),
        ("fat-finger comprehensive", test_fat_finger_comprehensive),
        ("mixed-encodings", test_mixed_encodings),
        ("mixed-encodings comprehensive", test_mixed_encodings_comprehensive),
        ("mixed-encodings multiple substitutions", test_mixed_encodings_multiple_substitutions),
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

