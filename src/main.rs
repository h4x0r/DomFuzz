use clap::Parser;
use futures::stream::{self, StreamExt};
use hickory_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};
use indicatif::{ProgressBar, ProgressStyle};
use std::sync::Arc;
use std::{
    collections::HashSet,
    io::{self, Write},
    time::Duration,
};
use tokio::sync::Semaphore;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

// Constants for timeout values
const RDAP_TIMEOUT_SECS: u64 = 5;
const DNS_TIMEOUT_SECS: u64 = 5;
const HTTP_TIMEOUT_SECS: u64 = 10;
const HTTP_CONTENT_TIMEOUT_SECS: u64 = 5;
const WHOIS_CONNECT_TIMEOUT_SECS: u64 = 10;
const WHOIS_WRITE_TIMEOUT_SECS: u64 = 5;
const WHOIS_READ_TIMEOUT_SECS: u64 = 10;
const RETRY_DELAY_MS: u64 = 500;

// Type alias for better error handling
type DomainCheckResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

// Global HTTP client for connection reuse and performance
lazy_static::lazy_static! {
    static ref HTTP_CLIENT: reqwest::Client = {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(RDAP_TIMEOUT_SECS))
            .user_agent("Mozilla/5.0 (compatible; DomFuzz/0.1)")
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client")
    };
}

#[derive(Parser)]
#[command(name = "domfuzz")]
#[command(
    about = "A Rust CLI tool for generating domain name variations using typosquatting techniques"
)]
#[command(after_help = "Available transformations grouped by category:

Character-level:
  1337speak, misspelling, fat-finger, mixed-encodings, bitsquatting

Phonetic/Semantic:
  homophones, cognitive, singular-plural

Number/Word:
  cardinal-substitution, ordinal-substitution

Structure:
  word-swap, hyphenation, subdomain, dot-insertion, dot-omission, dot-hyphen-sub

Extensions:
  tld-variations, intl-tld, wrong-sld, combosquatting, brand-confusion, domain-prefix, domain-suffix

Bundles:
  lookalike - Character-level transformations creating visually similar domains
             (1337speak, misspelling, fat-finger, mixed-encodings)
  system-fault - Hardware/system error transformations
             (bitsquatting)

Examples:
  domfuzz example.com                    (uses lookalike bundle by default)
  domfuzz -t system-fault example.com       (uses system-fault bundle)
  domfuzz -t 1337speak,fat-finger example.com
  domfuzz -t all example.com
  domfuzz -t misspellings -1 example.com")]
struct Cli {
    /// Domain to generate variations for
    domain: String,

    /// Transformations to enable (comma-separated). Default: 'lookalike' bundle. Use 'all' for all transformations
    #[arg(long, short = 't', value_delimiter = ',')]
    transformation: Vec<String>,

    /// Limit maximum number of variations to output
    #[arg(long, short = 'n')]
    max_variations: Option<usize>,

    /// Check domain availability status (requires network)
    #[arg(long, short = 's')]
    check_status: bool,

    /// Output only domains that are registered (not available) - implies --check-status
    #[arg(long, short = 'r')]
    only_registered: bool,

    /// Output only domains that are available (not registered) - implies --check-status
    #[arg(long, short = 'a')]
    only_available: bool,

    /// Path to dictionary file for combosquatting
    #[arg(long)]
    dictionary: Option<String>,

    /// Run each transformation individually, applying only one transformation per domain (default: enabled)
    #[arg(long, short = '1', default_value_t = true)]
    one_transformation: bool,

    /// Enable verbose output showing what the application is doing
    #[arg(long, short = 'v')]
    verbose: bool,

    /// Calculate and display similarity scores for generated variations
    #[arg(long)]
    similarity: bool,

    /// Filter results to minimum similarity threshold (0.0-1.0 or 0%-100%)
    #[arg(long, value_name = "THRESHOLD", default_value = "50%")]
    min_similarity: Option<String>,

    /// Batch size for streaming domain checking (domains processed per batch)
    #[arg(long, value_name = "SIZE", default_value = "20")]
    batch_size: usize,
}

/// Parse similarity threshold from string, supporting both decimal (0.0-1.0) and percentage (0%-100%) formats
fn parse_similarity_threshold(input: &str) -> Result<f64, String> {
    let input = input.trim();

    if input.ends_with('%') {
        // Parse percentage format (e.g., "73.28%")
        let percentage_str = input.trim_end_matches('%');
        match percentage_str.parse::<f64>() {
            Ok(percentage) => {
                if !(0.0..=100.0).contains(&percentage) {
                    Err(format!(
                        "Percentage must be between 0% and 100%, got: {}%",
                        percentage
                    ))
                } else {
                    Ok(percentage / 100.0)
                }
            }
            Err(_) => Err(format!("Invalid percentage format: {}", input)),
        }
    } else {
        // Parse decimal format (e.g., "0.7328")
        match input.parse::<f64>() {
            Ok(decimal) => {
                if !(0.0..=1.0).contains(&decimal) {
                    Err(format!(
                        "Decimal threshold must be between 0.0 and 1.0, got: {}",
                        decimal
                    ))
                } else {
                    Ok(decimal)
                }
            }
            Err(_) => Err(format!("Invalid similarity threshold format: {}", input)),
        }
    }
}

fn parse_transformations(transformations: &[String]) -> std::collections::HashSet<String> {
    let mut enabled = std::collections::HashSet::new();

    // If no transformations specified, use lookalike bundle by default
    if transformations.is_empty() {
        enabled.insert("lookalike".to_string());
    } else {
        for transformation in transformations {
            enabled.insert(transformation.to_lowercase());
        }
    }

    // Handle transformation bundles
    if enabled.contains("lookalike") {
        enabled.remove("lookalike");
        // Lookalike bundle: character-level transformations that create visually similar domains
        enabled.insert("1337speak".to_string());
        enabled.insert("1337speak".to_string());
        enabled.insert("misspelling".to_string());
        enabled.insert("fat-finger".to_string());
        enabled.insert("mixed-encodings".to_string());

        enabled.insert("fat-finger".to_string());
        // Character-level additions
    }

    // Handle system-fault bundle
    if enabled.contains("system-fault") {
        enabled.remove("system-fault");
        // System-fault bundle: errors caused by hardware/system failures
        enabled.insert("bitsquatting".to_string());
    }

    // If "all" is specified, add all transformation names
    if enabled.contains("all") {
        enabled.clear();
        // Basic Typos
        enabled.insert("1337speak".to_string());
        enabled.insert("misspelling".to_string());

        enabled.insert("fat-finger".to_string());

        // Character Manipulation
        enabled.insert("bitsquatting".to_string());

        enabled.insert("fat-finger".to_string());

        // Unicode/Script
        enabled.insert("mixed-encodings".to_string());

        // Phonetic/Semantic
        enabled.insert("homophones".to_string());

        enabled.insert("cognitive".to_string());
        enabled.insert("singular-plural".to_string());

        // Number/Word Substitution
        enabled.insert("cardinal-substitution".to_string());
        enabled.insert("ordinal-substitution".to_string());

        // Structure Manipulation
        enabled.insert("word-swap".to_string());
        enabled.insert("hyphenation".to_string());

        enabled.insert("subdomain".to_string());
        enabled.insert("dot-insertion".to_string());
        enabled.insert("dot-omission".to_string());
        enabled.insert("dot-hyphen-sub".to_string());

        // Domain Extensions
        enabled.insert("tld-variations".to_string());
        enabled.insert("intl-tld".to_string());
        enabled.insert("wrong-sld".to_string());
        enabled.insert("combosquatting".to_string());
        enabled.insert("brand-confusion".to_string());
        enabled.insert("domain-prefix".to_string());
        enabled.insert("domain-suffix".to_string());
    }

    enabled
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        eprintln!("DomFuzz starting with domain: {}", cli.domain);
        if cli.one_transformation {
            eprintln!("Mode: One transformation per domain");
        } else {
            eprintln!("Mode: Combo transformations (default)");
        }
        if cli.only_registered {
            eprintln!("Filter: Only showing registered domains");
        } else if cli.only_available {
            eprintln!("Filter: Only showing available domains");
        } else if cli.check_status {
            eprintln!("Status checking: Enabled");
        }
    }

    // --only-registered or --only-available implies --check-status
    let check_status = cli.check_status || cli.only_registered || cli.only_available;

    let (domain_name, tld) = parse_domain(&cli.domain);
    let original_registrable_domain = extract_registrable_domain(&cli.domain);
    let mut variations = HashSet::new();
    let mut variation_sources: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();

    // Parse enabled transformations
    let enabled_transformations = parse_transformations(&cli.transformation);

    // Generate combo transformations and collect results (unified with individual mode)
    if !cli.one_transformation {
        if cli.verbose {
            eprintln!("Starting combo transformation generation...");
        }
        let dict_words = if let Some(dict_file) = &cli.dictionary {
            load_dictionary(dict_file)
        } else {
            default_dictionary()
        };

        // Use unlimited by default for --combo, even with status checking
        let combo_limit = cli.max_variations;
        if cli.verbose {
            match combo_limit {
                Some(limit) => eprintln!("Generating combo transformations with limit: {}", limit),
                None => eprintln!("Generating unlimited combo transformations"),
            }
        }
        let output_limit = cli.max_variations.unwrap_or(usize::MAX);
        let parsed_min_similarity = if let Some(ref sim_str) = cli.min_similarity {
            match parse_similarity_threshold(sim_str) {
                Ok(threshold) => Some(threshold),
                Err(e) => {
                    eprintln!("Error parsing similarity threshold: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            None
        };
        let config = ComboConfig {
            domain: &domain_name,
            tld: &tld,
            max_variations: combo_limit,
            verbose: cli.verbose,
            only_registered: cli.only_registered,
            only_available: cli.only_available,
            output_count: output_limit,
            check_status,
            enabled_transformations: &enabled_transformations,
            min_similarity: parsed_min_similarity,
            batch_size: cli.batch_size,
        };
        generate_combo_attacks_streaming(&config, &dict_words).await;
        // Combo mode now handles its own output and status checking
        return;
    }

    if enabled_transformations.contains("1337speak") {
        if cli.verbose {
            eprintln!("Running character substitution transformation...");
        }
        let results = filter_valid_domains(generate_1337speak(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} 1337speak variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("1337speak".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("misspelling") {
        if cli.verbose {
            eprintln!("Running misspellings transformation...");
        }
        let results = filter_valid_domains(generate_misspelling(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} misspellings variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("misspelling".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("mixed-encodings") {
        if cli.verbose {
            eprintln!("Running homoglyphs transformation...");
        }
        let results = filter_valid_domains(generate_mixed_encodings(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} homoglyphs variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("mixed-encodings".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("tld-variations") {
        if cli.verbose {
            eprintln!("Running tld-variations transformation...");
        }
        let results = filter_valid_domains(generate_tld_variations(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} tld-variations variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("tld-variations".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("word-swap") {
        if cli.verbose {
            eprintln!("Running word-swap transformation...");
        }
        let results = filter_valid_domains(generate_word_swaps(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} word-swap variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("word-swap".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("bitsquatting") {
        if cli.verbose {
            eprintln!("Running bitsquatting transformation...");
        }
        let results = filter_valid_domains(generate_bitsquatting(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} bitsquatting variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("bitsquatting".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("fat-finger") {
        if cli.verbose {
            eprintln!("Running repetition transformation...");
        }
        let results = filter_valid_domains(generate_fat_finger(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} repetition variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("fat-finger".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("hyphenation") {
        if cli.verbose {
            eprintln!("Running hyphenation transformation...");
        }
        let results = filter_valid_domains(generate_hyphenation(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} hyphenation variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("hyphenation".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("subdomain") {
        if cli.verbose {
            eprintln!("Running subdomain transformation...");
        }
        let results = filter_valid_domains(generate_subdomain_injection(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} subdomain variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("subdomain".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("combosquatting") {
        if cli.verbose {
            eprintln!("Running combosquatting transformation...");
        }
        let dict_words = if let Some(dict_file) = &cli.dictionary {
            load_dictionary(dict_file)
        } else {
            default_dictionary()
        };
        let results =
            filter_valid_domains(generate_combosquatting(&domain_name, &tld, &dict_words));
        if cli.verbose {
            eprintln!("  Generated {} combosquatting variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("combosquatting".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("mixed-encodings") {
        if cli.verbose {
            eprintln!("Running idn-homograph transformation...");
        }
        let results = filter_valid_domains(generate_mixed_encodings(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} idn-homograph variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("mixed-encodings".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("mixed-encodings") {
        if cli.verbose {
            eprintln!("Running mixed-script transformation...");
        }
        let results = filter_valid_domains(generate_mixed_encodings(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} mixed-script variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("mixed-encodings".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("mixed-encodings") {
        if cli.verbose {
            eprintln!("Running extended-unicode transformation...");
        }
        let results = filter_valid_domains(generate_mixed_encodings(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} extended-unicode variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("mixed-encodings".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("brand-confusion") {
        if cli.verbose {
            eprintln!("Running brand-confusion transformation...");
        }
        let results = filter_valid_domains(generate_brand_confusion(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} brand-confusion variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("brand-confusion".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("intl-tld") {
        if cli.verbose {
            eprintln!("Running intl-tld transformation...");
        }
        let results = filter_valid_domains(generate_intl_tld(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} intl-tld variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("intl-tld".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("cognitive") {
        if cli.verbose {
            eprintln!("Running cognitive transformation...");
        }
        let results = filter_valid_domains(generate_cognitive(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} cognitive variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("cognitive".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("dot-insertion") {
        if cli.verbose {
            eprintln!("Running dot-insertion transformation...");
        }
        let results = filter_valid_domains(generate_dot_insertion(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} dot-insertion variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("dot-insertion".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("dot-omission") {
        if cli.verbose {
            eprintln!("Running dot-omission transformation...");
        }
        let results = filter_valid_domains(generate_dot_omission(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} dot-omission variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("dot-omission".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("dot-hyphen-sub") {
        if cli.verbose {
            eprintln!("Running dot-hyphen-sub transformation...");
        }
        let results = filter_valid_domains(generate_dot_hyphen_substitution(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} dot-hyphen-sub variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("dot-hyphen-sub".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("misspelling") {
        if cli.verbose {
            eprintln!("Running double-char-replacement transformation...");
        }
        let results = filter_valid_domains(generate_misspelling(&domain_name, &tld));
        if cli.verbose {
            eprintln!(
                "  Generated {} double-char-replacement variations",
                results.len()
            );
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("misspelling".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("fat-finger") {
        if cli.verbose {
            eprintln!("Running fat-finger transformation...");
        }
        let results = filter_valid_domains(generate_fat_finger(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} fat-finger variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("fat-finger".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("cardinal-substitution") {
        if cli.verbose {
            eprintln!("Running cardinal-substitution transformation...");
        }
        let results = filter_valid_domains(generate_cardinal_substitution(&domain_name, &tld));
        if cli.verbose {
            eprintln!(
                "  Generated {} cardinal-substitution variations",
                results.len()
            );
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("cardinal-substitution".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("ordinal-substitution") {
        if cli.verbose {
            eprintln!("Running ordinal-substitution transformation...");
        }
        let results = filter_valid_domains(generate_ordinal_substitution(&domain_name, &tld));
        if cli.verbose {
            eprintln!(
                "  Generated {} ordinal-substitution variations",
                results.len()
            );
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("ordinal-substitution".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("homophones") {
        if cli.verbose {
            eprintln!("Running homophones transformation...");
        }
        let results = filter_valid_domains(generate_homophones(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} homophones variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("homophones".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("singular-plural") {
        if cli.verbose {
            eprintln!("Running singular-plural transformation...");
        }
        let results = filter_valid_domains(generate_singular_plural(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} singular-plural variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("singular-plural".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("wrong-sld") {
        if cli.verbose {
            eprintln!("Running wrong-sld transformation...");
        }
        let results = filter_valid_domains(generate_wrong_sld(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} wrong-sld variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("wrong-sld".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("domain-prefix") {
        if cli.verbose {
            eprintln!("Running domain-prefix transformation...");
        }
        let results = filter_valid_domains(generate_domain_prefix(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} domain-prefix variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("domain-prefix".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("domain-suffix") {
        if cli.verbose {
            eprintln!("Running domain-suffix transformation...");
        }
        let results = filter_valid_domains(generate_domain_suffix(&domain_name, &tld));
        if cli.verbose {
            eprintln!("  Generated {} domain-suffix variations", results.len());
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("domain-suffix".to_string());
        }
        variations.extend(results);
    }

    if enabled_transformations.contains("cyrillic-comprehensive") {
        if cli.verbose {
            eprintln!("Running cyrillic-comprehensive transformation...");
        }
        let results = filter_valid_domains(generate_mixed_encodings(&domain_name, &tld));
        if cli.verbose {
            eprintln!(
                "  Generated {} cyrillic-comprehensive variations",
                results.len()
            );
        }
        for result in &results {
            variation_sources
                .entry(result.clone())
                .or_insert("cyrillic-comprehensive".to_string());
        }
        variations.extend(results);
    }

    // Apply exact max_variations limit - generate more if needed to replace invalid ones
    let mut all_variations: Vec<_> = variations.into_iter().collect();
    // Note: Will sort by similarity score after calculating scores

    let output_count = if let Some(max) = cli.max_variations {
        if all_variations.len() < max {
            // We need more variations to reach the exact count requested
            // Use combo-style generation to create additional unique variations
            let target_additional = max - all_variations.len();
            let mut additional_variations = HashSet::new();
            let mut attempts = 0;
            let max_attempts = target_additional * 20;

            // Generate combinations of existing transformations to create new variations
            use rand::seq::SliceRandom;
            use rand::thread_rng;
            use rand::Rng;
            let mut rng = thread_rng();

            // Define available generators

            #[allow(clippy::type_complexity, clippy::redundant_closure)]
            let generators: Vec<(&str, Box<dyn Fn(&str, &str) -> Vec<String>>)> = vec![
                ("char_sub", Box::new(|d, t| generate_1337speak(d, t))),
                (
                    "mixed-encodings",
                    Box::new(|d, t| generate_mixed_encodings(d, t)),
                ),
                ("misspelling", Box::new(|d, t| generate_misspelling(d, t))),
                (
                    "tld_variations",
                    Box::new(|d, t| generate_tld_variations(d, t)),
                ),
                ("fat-finger", Box::new(|d, t| generate_fat_finger(d, t))),
                ("hyphenation", Box::new(|d, t| generate_hyphenation(d, t))),
            ];

            while additional_variations.len() < target_additional && attempts < max_attempts {
                attempts += 1;

                // Generate a new variation by applying 2-3 random transformations in sequence
                let mut current_domain = domain_name.clone();
                let mut current_tld = tld.clone();
                let num_transforms = rng.gen_range(2..=3);

                for _ in 0..num_transforms {
                    if let Some((_, generator)) = generators.choose(&mut rng) {
                        let results =
                            filter_valid_domains(generator(&current_domain, &current_tld));
                        if let Some(result) = results.choose(&mut rng) {
                            let (new_domain, new_tld) = parse_domain(result);
                            current_domain = new_domain;
                            current_tld = new_tld;
                        }
                    }
                }

                let final_domain = format!("{}.{}", current_domain, current_tld);
                if final_domain != format!("{}.{}", domain_name, tld)
                    && is_valid_domain(&final_domain)
                    && !all_variations.contains(&final_domain)
                    && !additional_variations.contains(&final_domain)
                {
                    additional_variations.insert(final_domain);
                }
            }

            // Add the additional variations
            all_variations.extend(additional_variations);
            // Note: Will sort by similarity score after calculating scores
        }

        // Return exactly the requested number
        max.min(all_variations.len())
    } else if cli.only_registered {
        // For unlimited combo with --only-registered, don't limit output count
        usize::MAX
    } else {
        all_variations.len()
    };

    // Calculate similarity scores for all variations (always needed for output format)
    let mut similarity_scores: Vec<SimilarityScore> = Vec::new();
    {
        let original_domain = format!("{}.{}", domain_name, tld);
        for variation in &all_variations {
            let unknown_type = "unknown".to_string();
            let transformation_type = variation_sources.get(variation).unwrap_or(&unknown_type);
            let score = calculate_similarity(&original_domain, variation, transformation_type);

            // Apply minimum similarity filter if specified
            if let Some(ref sim_str) = cli.min_similarity {
                let min_sim = match parse_similarity_threshold(sim_str) {
                    Ok(threshold) => threshold,
                    Err(e) => {
                        eprintln!("Error parsing similarity threshold: {}", e);
                        std::process::exit(1);
                    }
                };
                if score.combined_score >= min_sim {
                    similarity_scores.push(score);
                }
            } else {
                similarity_scores.push(score);
            }
        }

        // Sort similarity scores by combined_score in descending order (highest similarity first)
        similarity_scores.sort_by(|a, b| {
            b.combined_score
                .partial_cmp(&a.combined_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    // Always use similarity-sorted variations (highest similarity first)
    let sorted_variations: Vec<&str> = similarity_scores
        .iter()
        .map(|s| s.domain.as_str())
        .collect();

    let actual_output_count = if check_status {
        // Filter domains to avoid duplicates with original
        let domains_to_check: Vec<String> = sorted_variations
            .iter()
            .take(output_count)
            .filter(|variation| {
                let variation_registrable_domain = extract_registrable_domain(variation);
                variation_registrable_domain != original_registrable_domain
            })
            .map(|s| s.to_string())
            .collect();

        // Use concurrent domain checking with reasonable concurrency limit
        let concurrency = 15; // Good balance between speed and not overwhelming servers

        let results = check_domains_concurrent(domains_to_check, concurrency).await;

        clear_progress_line();
        let mut output_counter = 0;

        // Process results and apply filters
        for (domain, status) in results {
            let should_show = if cli.only_registered {
                status != "available"
            } else if cli.only_available {
                status == "available"
            } else {
                true // Show all domains with status
            };

            if should_show {
                // Find similarity score for this domain
                if let Some(score) = similarity_scores.iter().find(|s| s.domain == domain) {
                    let transformation = variation_sources
                        .get(&domain)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    println!(
                        "{:.2}%, {}, {}, {}",
                        score.combined_score * 100.0,
                        domain,
                        transformation,
                        status
                    );
                } else {
                    let transformation = variation_sources
                        .get(&domain)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    println!("0.00%, {}, {}, {}", domain, transformation, status);
                }
                output_counter += 1;
            }
        }
        output_counter
    } else {
        for variation in sorted_variations.iter().take(output_count) {
            if cli.verbose {
                if let Some(attack) = variation_sources.get(*variation) {
                    let original_domain = format!("{}.{}", domain_name, tld);
                    let score = calculate_similarity(&original_domain, variation, attack);
                    eprintln!("  Applied {} transformation: {}.{} -> {} (visual:{:.3}, cognitive:{:.3}, combined:{:.3})", 
                        attack, domain_name, tld, variation, score.visual_score, score.cognitive_score, score.combined_score);
                    // Always show combined similarity score with transformation source
                    if let Some(score) = similarity_scores.iter().find(|s| s.domain == *variation) {
                        println!(
                            "{:.2}%, {}, {}",
                            score.combined_score * 100.0,
                            variation,
                            attack
                        );
                    } else {
                        println!("0.00%, {}, {}", variation, attack);
                    }
                } else {
                    // Always show combined similarity score with transformation source
                    if let Some(score) = similarity_scores.iter().find(|s| s.domain == *variation) {
                        let transformation = variation_sources
                            .get(*variation)
                            .map(|s| s.as_str())
                            .unwrap_or("unknown");
                        println!(
                            "{:.2}%, {}, {}",
                            score.combined_score * 100.0,
                            variation,
                            transformation
                        );
                    } else {
                        let transformation = variation_sources
                            .get(*variation)
                            .map(|s| s.as_str())
                            .unwrap_or("unknown");
                        println!("0.00%, {}, {}", variation, transformation);
                    }
                }
            } else {
                // Always show combined similarity score with transformation source
                if let Some(score) = similarity_scores.iter().find(|s| s.domain == *variation) {
                    let transformation = variation_sources
                        .get(*variation)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    println!(
                        "{:.2}%, {}, {}",
                        score.combined_score * 100.0,
                        variation,
                        transformation
                    );
                } else {
                    let transformation = variation_sources
                        .get(*variation)
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    println!("0.00%, {}, {}", variation, transformation);
                }
            }
        }
        output_count
    };

    if cli.only_registered {
        eprintln!("Found {} registered variations ", actual_output_count);
    } else {
        eprintln!("Generated {} variations ", actual_output_count);
    }
}

/// Concurrent domain status checking with configurable concurrency limit
async fn check_domains_concurrent(
    domains: Vec<String>,
    concurrency: usize,
) -> Vec<(String, String)> {
    let semaphore = Arc::new(Semaphore::new(concurrency));

    // Create progress bar
    let pb = ProgressBar::new(domains.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos:>7}/{len:7} {msg}",
            )
            .expect("Failed to set progress bar template")
            .progress_chars("█▉▊▋▌▍▎▏  "),
    );
    pb.set_message("Checking domains...");

    let pb = Arc::new(pb);

    let results: Vec<(String, String)> = stream::iter(domains)
        .map(|domain| {
            let sem = Arc::clone(&semaphore);
            let pb = Arc::clone(&pb);
            async move {
                let _permit = sem.acquire().await.expect("Failed to acquire semaphore");
                let status = check_domain_status(&domain).await;
                pb.inc(1);
                (domain, status)
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    pb.finish_with_message("Domain checking complete!");

    results
}

/// Fast domain status checking using RDAP (Registration Data Access Protocol) first,
/// with WHOIS/DNS fallback for unknown TLDs. This provides significant performance
/// improvements over the original WHOIS-first approach:
///
/// Performance improvements:
/// - RDAP uses HTTP/HTTPS with structured JSON responses (vs TCP WHOIS text parsing)
/// - HTTP 404 = available, 200 = registered (simple status determination)
/// - Built-in endpoint mapping for 30+ major TLDs avoids discovery overhead
/// - Typical speedup: 3-5x faster for supported TLDs
/// - Concurrent processing: 5-10x speedup with parallel requests
async fn check_domain_status(domain: &str) -> String {
    // Extract the registrable domain
    let registrable_domain = extract_registrable_domain(domain);

    // Try fast RDAP check first (modern protocol, HTTP-based)
    if let Ok(status) = check_domain_rdap(&registrable_domain).await {
        return status;
    }

    // Fallback to the original implementation for unknown TLDs
    check_domain_status_legacy(&registrable_domain).await
}

/// Fast RDAP-based domain checking using built-in registry mapping
async fn check_domain_rdap(domain: &str) -> DomainCheckResult<String> {
    let tld = extract_tld(domain)?;

    // Get RDAP endpoint for this TLD
    let endpoint = get_rdap_endpoint(&tld)?;

    // Build RDAP URL
    let rdap_url = format!("{}{}", endpoint, domain);

    // Use shared HTTP client for connection reuse

    // Make RDAP request using shared client
    let response = HTTP_CLIENT.get(&rdap_url).send().await?;

    match response.status() {
        reqwest::StatusCode::OK => {
            // Domain exists (registered), check if it might be parked
            if let Ok(json) = response.json::<serde_json::Value>().await {
                if is_domain_parked_rdap(&json) {
                    Ok("parked".to_string())
                } else {
                    Ok("registered".to_string())
                }
            } else {
                Ok("registered".to_string())
            }
        }
        reqwest::StatusCode::NOT_FOUND => Ok("available".to_string()),
        reqwest::StatusCode::TOO_MANY_REQUESTS => {
            // Rate limited, wait and try once more
            tokio::time::sleep(Duration::from_millis(RETRY_DELAY_MS)).await;
            let retry_response = HTTP_CLIENT.get(&rdap_url).send().await?;
            match retry_response.status() {
                reqwest::StatusCode::OK => Ok("registered".to_string()),
                reqwest::StatusCode::NOT_FOUND => Ok("available".to_string()),
                _ => Err("RDAP server error after retry".into()),
            }
        }
        _ => Err(format!("RDAP server returned status: {}", response.status()).into()),
    }
}

/// Check if domain appears to be parked based on RDAP data
fn is_domain_parked_rdap(json: &serde_json::Value) -> bool {
    // Check status codes for parking indicators
    if let Some(statuses) = json.get("status").and_then(|s| s.as_array()) {
        for status in statuses {
            if let Some(status_str) = status.as_str() {
                let status_lower = status_str.to_lowercase();
                if status_lower.contains("client hold")
                    || status_lower.contains("redemption")
                    || status_lower.contains("pending delete")
                {
                    return true;
                }
            }
        }
    }

    // Check entities for parking service registrars
    if let Some(entities) = json.get("entities").and_then(|e| e.as_array()) {
        for entity in entities {
            if let Some(roles) = entity.get("roles").and_then(|r| r.as_array()) {
                if roles.iter().any(|role| role.as_str() == Some("registrar")) {
                    if let Some(name) = extract_registrar_name(entity) {
                        let name_lower = name.to_lowercase();
                        if name_lower.contains("sedo")
                            || name_lower.contains("parking")
                            || name_lower.contains("bodis")
                            || name_lower.contains("hugedomains")
                        {
                            return true;
                        }
                    }
                }
            }
        }
    }

    false
}

/// Extract registrar name from RDAP entity
fn extract_registrar_name(entity: &serde_json::Value) -> Option<String> {
    // Try vcardArray first
    if let Some(name) = extract_vcard_name(entity) {
        return Some(name);
    }

    // Fallback to publicIds or handle
    if let Some(public_ids) = entity.get("publicIds").and_then(|p| p.as_array()) {
        if let Some(id) = public_ids
            .first()
            .and_then(|id| id.get("identifier"))
            .and_then(|i| i.as_str())
        {
            return Some(id.to_string());
        }
    }

    entity
        .get("handle")
        .or_else(|| entity.get("name"))
        .and_then(|n| n.as_str())
        .map(String::from)
}

/// Extract organization name from vCard format
fn extract_vcard_name(entity: &serde_json::Value) -> Option<String> {
    entity
        .get("vcardArray")
        .and_then(|v| v.as_array())
        .and_then(|a| a.get(1))
        .and_then(|a| a.as_array())
        .and_then(|items| {
            for item in items {
                if let Some(item_array) = item.as_array() {
                    if item_array.len() >= 4 {
                        if let Some(first) = item_array.first().and_then(|f| f.as_str()) {
                            if first == "fn" {
                                return item_array
                                    .get(3)
                                    .and_then(|n| n.as_str())
                                    .map(String::from);
                            }
                        }
                    }
                }
            }
            None
        })
}

/// Get RDAP endpoint for a TLD
fn get_rdap_endpoint(tld: &str) -> DomainCheckResult<&'static str> {
    let endpoint = match tld.to_lowercase().as_str() {
        // Major gTLDs
        "com" => "https://rdap.verisign.com/com/v1/domain/",
        "net" => "https://rdap.verisign.com/net/v1/domain/",
        "org" => "https://rdap.publicinterestregistry.org/rdap/domain/",
        "info" => "https://rdap.identitydigital.services/rdap/domain/",
        "biz" => "https://rdap.nic.biz/domain/",
        // Google TLDs
        "app" => "https://rdap.nic.google/domain/",
        "dev" => "https://rdap.nic.google/domain/",
        "page" => "https://rdap.nic.google/domain/",
        // Other popular TLDs
        "xyz" => "https://rdap.nic.xyz/domain/",
        "tech" => "https://rdap.nic.tech/domain/",
        "online" => "https://rdap.nic.online/domain/",
        "site" => "https://rdap.nic.site/domain/",
        // ccTLDs
        "io" => "https://rdap.identitydigital.services/rdap/domain/",
        "ai" => "https://rdap.nic.ai/domain/",
        "co" => "https://rdap.nic.co/domain/",
        "me" => "https://rdap.nic.me/domain/",
        "us" => "https://rdap.nic.us/domain/",
        "uk" => "https://rdap.nominet.uk/domain/",
        "eu" => "https://rdap.eu.org/domain/",
        "de" => "https://rdap.denic.de/domain/",
        "ca" => "https://rdap.cira.ca/domain/",
        "au" => "https://rdap.auda.org.au/domain/",
        "fr" => "https://rdap.nic.fr/domain/",
        "jp" => "https://rdap.jprs.jp/domain/",
        "br" => "https://rdap.registro.br/domain/",
        "in" => "https://rdap.registry.in/domain/",
        "cn" => "https://rdap.cnnic.cn/domain/",
        "tv" => "https://rdap.verisign.com/tv/v1/domain/",
        "cc" => "https://rdap.verisign.com/cc/v1/domain/",
        _ => return Err(format!("No RDAP endpoint known for TLD: {}", tld).into()),
    };

    Ok(endpoint)
}

/// Extract TLD from domain
fn extract_tld(domain: &str) -> DomainCheckResult<String> {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return Err("Invalid domain format".into());
    }
    Ok(parts
        .last()
        .expect("Domain must have at least one part after split")
        .to_lowercase())
}

/// Legacy domain checking (fallback for unknown TLDs)
async fn check_domain_status_legacy(domain: &str) -> String {
    // First check WHOIS for the most accurate information
    if let Ok(whois_result) = check_whois(domain).await {
        return whois_result;
    }

    // Fallback to DNS + HTTP checking
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let dns_result = timeout(
        Duration::from_secs(DNS_TIMEOUT_SECS),
        resolver.lookup_ip(domain),
    )
    .await;

    match dns_result {
        Ok(Ok(lookup)) => {
            if lookup.iter().count() == 0 {
                return "available".to_string();
            }

            // Domain has DNS records, check if it's parked or active
            // Use shared HTTP client for better performance

            // Try HTTP first, then HTTPS
            for protocol in ["http", "https"] {
                let url = format!("{}://{}", protocol, domain);
                if let Ok(Ok(resp)) = timeout(
                    Duration::from_secs(HTTP_TIMEOUT_SECS),
                    HTTP_CLIENT.get(&url).send(),
                )
                .await
                {
                    if resp.status().is_success() {
                        if let Ok(Ok(content)) =
                            timeout(Duration::from_secs(HTTP_CONTENT_TIMEOUT_SECS), resp.text())
                                .await
                        {
                            let content_lower = content.to_lowercase();
                            if content_lower.contains("parked")
                                || content_lower.contains("domain for sale")
                                || content_lower.contains("this domain may be for sale")
                                || content_lower.contains("godaddy")
                                    && content_lower.contains("parked")
                                || content_lower.contains("sedo")
                                || content_lower.contains("parking")
                                || content_lower.contains("under construction")
                                || content_lower.contains("coming soon")
                            {
                                return "parked".to_string();
                            }
                        }
                        return "registered".to_string();
                    }
                }
            }

            "registered".to_string()
        }
        Ok(Err(_)) => "available".to_string(),
        Err(_) => "timeout".to_string(),
    }
}

async fn check_whois(domain: &str) -> DomainCheckResult<String> {
    let tld = domain.split('.').next_back().unwrap_or("");
    let whois_server = get_whois_server(tld);

    // Connect to WHOIS server
    let mut stream = timeout(
        Duration::from_secs(WHOIS_CONNECT_TIMEOUT_SECS),
        TcpStream::connect(&whois_server),
    )
    .await??;

    // Send WHOIS query
    let query = format!(
        "{}
",
        domain
    );
    timeout(
        Duration::from_secs(WHOIS_WRITE_TIMEOUT_SECS),
        stream.write_all(query.as_bytes()),
    )
    .await??;

    // Read response
    let mut response = Vec::new();
    timeout(
        Duration::from_secs(WHOIS_READ_TIMEOUT_SECS),
        stream.read_to_end(&mut response),
    )
    .await??;
    let whois_data = String::from_utf8_lossy(&response).to_lowercase();

    // Analyze WHOIS response
    if whois_data.contains("no match")
        || whois_data.contains("not found")
        || whois_data.contains("no entries found")
        || whois_data.contains("domain status: available")
        || whois_data.contains("domain not found")
        || whois_data.contains("no data found")
    {
        Ok("available".to_string())
    } else if whois_data.contains("registrar:")
        || whois_data.contains("registrant:")
        || whois_data.contains("creation date:")
        || whois_data.contains("created:")
    {
        // Check if it's parked based on WHOIS data
        if whois_data.contains("parked")
            || whois_data.contains("parking")
            || whois_data.contains("domain for sale")
            || whois_data.contains("sedo")
            || whois_data.contains("bodis")
            || whois_data.contains("sedoparking")
        {
            Ok("parked".to_string())
        } else {
            Ok("registered".to_string())
        }
    } else {
        Err("unable to determine status".into())
    }
}

fn get_whois_server(tld: &str) -> String {
    match tld {
        "com" | "net" => "whois.verisign-grs.com:43".to_string(),
        "org" => "whois.pir.org:43".to_string(),
        "info" => "whois.afilias.net:43".to_string(),
        "biz" => "whois.neulevel.biz:43".to_string(),
        "us" => "whois.nic.us:43".to_string(),
        "co" => "whois.nic.co:43".to_string(),
        "io" => "whois.nic.io:43".to_string(),
        "me" => "whois.nic.me:43".to_string(),
        "uk" => "whois.nic.uk:43".to_string(),
        "ca" => "whois.cira.ca:43".to_string(),
        "de" => "whois.denic.de:43".to_string(),
        "fr" => "whois.afnic.fr:43".to_string(),
        "ru" => "whois.tcinet.ru:43".to_string(),
        "cn" => "whois.cnnic.net.cn:43".to_string(),
        "jp" => "whois.jprs.jp:43".to_string(),
        "au" => "whois.auda.org.au:43".to_string(),
        "br" => "whois.registro.br:43".to_string(),
        "tk" => "whois.dot.tk:43".to_string(),
        "ml" => "whois.dot.ml:43".to_string(),
        "ga" => "whois.dot.ga:43".to_string(),
        "cf" => "whois.dot.cf:43".to_string(),
        "app" => "whois.nic.google:43".to_string(),
        "dev" => "whois.nic.google:43".to_string(),
        "tech" => "whois.nic.tech:43".to_string(),
        _ => "whois.iana.org:43".to_string(), // Fallback to IANA
    }
}

fn is_valid_domain(domain: &str) -> bool {
    // Check overall length limit (253 characters for FQDN)
    if domain.len() > 253 || domain.is_empty() {
        return false;
    }

    // Domain can't start or end with dot
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }

    // Check for consecutive dots
    if domain.contains("..") {
        return false;
    }

    // Split into labels and validate each
    let labels: Vec<&str> = domain.split('.').collect();

    for label in &labels {
        // Label can't be empty (handled by consecutive dots check above, but being explicit)
        if label.is_empty() {
            return false;
        }

        // Label length limit (63 characters)
        if label.len() > 63 {
            return false;
        }

        // Label can't start or end with hyphen
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }

        // Label must contain only valid characters (alphanumeric and hyphens)
        // Note: We're being permissive to allow Unicode/IDN characters for our use case
        for ch in label.chars() {
            if !ch.is_alphanumeric() && ch != '-' && !ch.is_ascii() {
                // Allow non-ASCII for Unicode/IDN transformations, but reject other invalid chars
                continue;
            }
            if !ch.is_alphanumeric() && ch != '-' && ch.is_ascii() && !ch.is_ascii_alphanumeric() {
                return false;
            }
        }
    }

    // Must have at least one dot (domain.tld format)
    if labels.len() < 2 {
        return false;
    }

    // TLD (last label) must be at least 2 characters
    if let Some(tld) = labels.last() {
        if tld.len() < 2 {
            return false;
        }
    }

    true
}

fn filter_valid_domains(variations: Vec<String>) -> Vec<String> {
    variations
        .into_iter()
        .filter(|domain| is_valid_domain(domain))
        .map(|domain| domain.to_lowercase())
        .collect()
}

fn clear_progress_line() {
    eprint!("\r\x1b[K"); // Clear the current line
    let _ = io::stderr().flush(); // Ignore flush errors
}

// New function that collects results instead of printing immediately with concurrent domain checking
struct ComboConfig<'a> {
    domain: &'a str,
    tld: &'a str,
    max_variations: Option<usize>,
    verbose: bool,
    only_registered: bool,
    only_available: bool,
    output_count: usize,
    check_status: bool,
    enabled_transformations: &'a std::collections::HashSet<String>,
    min_similarity: Option<f64>,
    batch_size: usize,
}

async fn generate_combo_attacks_streaming(config: &ComboConfig<'_>, _dict_words: &[String]) {
    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use rand::Rng;

    let mut generated_domains = std::collections::HashSet::new();
    let mut rng = thread_rng();
    let mut current_batch: Vec<(String, SimilarityScore)> = Vec::new();
    let mut total_output_count = 0;

    // Define all available transformation functions with names matching CLI arguments
    #[allow(clippy::type_complexity, clippy::redundant_closure)]
    let all_transformation_functions: Vec<(&str, Box<dyn Fn(&str, &str) -> Vec<String>>)> = vec![
        ("1337speak", Box::new(|d, t| generate_1337speak(d, t))),
        (
            "mixed-encodings",
            Box::new(|d, t| generate_mixed_encodings(d, t)),
        ),
        ("misspelling", Box::new(|d, t| generate_misspelling(d, t))),
        ("keyboard", Box::new(|d, t| generate_misspelling(d, t))),
        ("fat-finger", Box::new(|d, t| generate_fat_finger(d, t))),
        ("word-swap", Box::new(|d, t| generate_word_swaps(d, t))),
        ("bitsquatting", Box::new(|d, t| generate_bitsquatting(d, t))),
        (
            "dot-insertion",
            Box::new(|d, t| generate_dot_insertion(d, t)),
        ),
        ("dot-omission", Box::new(|d, t| generate_dot_omission(d, t))),
        (
            "cardinal-substitution",
            Box::new(|d, t| generate_cardinal_substitution(d, t)),
        ),
        (
            "ordinal-substitution",
            Box::new(|d, t| generate_ordinal_substitution(d, t)),
        ),
        ("homophones", Box::new(|d, t| generate_homophones(d, t))),
        (
            "singular-plural",
            Box::new(|d, t| generate_singular_plural(d, t)),
        ),
        (
            "cyrillic-comprehensive",
            Box::new(|d, t| generate_mixed_encodings(d, t)),
        ),
        (
            "tld-variations",
            Box::new(|d, t| generate_tld_variations(d, t)),
        ),
        (
            "brand-confusion",
            Box::new(|d, t| generate_brand_confusion(d, t)),
        ),
        ("intl-tld", Box::new(|d, t| generate_intl_tld(d, t))),
        ("cognitive", Box::new(|d, t| generate_cognitive(d, t))),
        (
            "dot-hyphen-sub",
            Box::new(|d, t| generate_dot_hyphen_substitution(d, t)),
        ),
        (
            "subdomain",
            Box::new(|d, t| generate_subdomain_injection(d, t)),
        ),
        (
            "combosquatting",
            Box::new(|d, t| generate_combosquatting(d, t, _dict_words)),
        ),
        ("wrong-sld", Box::new(|d, t| generate_wrong_sld(d, t))),
        (
            "domain-prefix",
            Box::new(|d, t| generate_domain_prefix(d, t)),
        ),
        (
            "domain-suffix",
            Box::new(|d, t| generate_domain_suffix(d, t)),
        ),
    ];

    // Filter transformation functions based on enabled transformations
    #[allow(clippy::type_complexity)]
    let transformation_functions: Vec<(&str, Box<dyn Fn(&str, &str) -> Vec<String>>)> =
        all_transformation_functions
            .into_iter()
            .filter(|(name, _)| config.enabled_transformations.contains(*name))
            .collect();

    // Generate combo variations by applying random sequences of transformations
    let target_variations = config.max_variations.unwrap_or(usize::MAX); // Unlimited by default
    let mut attempts = 0;
    let max_attempts = config.max_variations.map_or(usize::MAX, |max| max * 10); // Unlimited attempts for unlimited generation

    while (config.max_variations.is_none() || total_output_count < target_variations)
        && attempts < max_attempts
        && total_output_count < config.output_count
    {
        attempts += 1;

        let mut current_domain = config.domain.to_string();
        let mut current_tld = config.tld.to_string();
        let mut applied_attacks: Vec<&str> = Vec::new();

        // Randomly choose number of transformations (1-5)
        let num_attacks = rng.gen_range(2..=5);

        // Apply random transformations (allowing repeats)
        for _ in 0..num_attacks {
            if let Some((attack_name, transformation_fn)) =
                transformation_functions.choose(&mut rng)
            {
                // Apply the transformation and randomly select one result
                let transformation_results = transformation_fn(&current_domain, &current_tld);
                if !transformation_results.is_empty() {
                    if let Some(selected_result) = transformation_results.choose(&mut rng) {
                        if config.verbose {
                            let original_domain = format!("{}.{}", config.domain, config.tld);
                            let score = calculate_similarity(
                                &original_domain,
                                selected_result,
                                attack_name,
                            );
                            eprintln!("  Applied {} transformation: {}.{} -> {} (visual:{:.3}, cognitive:{:.3}, combined:{:.3})", 
                                attack_name, current_domain, current_tld, selected_result,
                                score.visual_score, score.cognitive_score, score.combined_score);
                        }
                        // Parse the result to separate domain and TLD for next iteration
                        let (parsed_domain, parsed_tld) = parse_domain(selected_result);
                        current_domain = parsed_domain;
                        current_tld = parsed_tld;
                        applied_attacks.push(attack_name);
                    }
                }
            }
        }

        // Create the final domain name for this attempt
        let final_domain = format!("{}.{}", current_domain, current_tld);

        // Only add if we successfully applied at least 1 transformation
        if !applied_attacks.is_empty() {
            let lowercase_original = format!("{}.{}", config.domain, config.tld).to_lowercase();

            if final_domain.to_lowercase() != lowercase_original
                && !generated_domains.contains(&final_domain)
                && is_valid_domain(&final_domain)
            {
                generated_domains.insert(final_domain.clone());

                // Calculate similarity score
                let original_domain = format!("{}.{}", config.domain, config.tld);
                let score = calculate_similarity(&original_domain, &final_domain, "combo");

                // Check if this domain meets minimum similarity threshold
                let meets_threshold = if let Some(min_sim) = config.min_similarity {
                    score.combined_score >= min_sim
                } else {
                    true // No threshold specified, accept all domains
                };

                // Only add domains that meet the similarity threshold
                if meets_threshold {
                    current_batch.push((final_domain, score));

                    // Process batch when it reaches the specified size
                    if current_batch.len() >= config.batch_size {
                        let batch_count = process_batch(
                            &mut current_batch,
                            config.check_status,
                            config.only_registered,
                            config.only_available,
                            &mut total_output_count,
                            config.output_count,
                        )
                        .await;
                        if batch_count == 0 {
                            break; // Stop if we've reached the output limit
                        }
                    }
                }
                // If doesn't meet threshold, continue loop to generate another domain
            }
        }
    }

    // Process any remaining domains in the final batch
    if !current_batch.is_empty() && total_output_count < config.output_count {
        process_batch(
            &mut current_batch,
            config.check_status,
            config.only_registered,
            config.only_available,
            &mut total_output_count,
            config.output_count,
        )
        .await;
    }
}

/// Process a batch of domains for streaming output
async fn process_batch(
    batch: &mut Vec<(String, SimilarityScore)>,
    check_status: bool,
    only_registered: bool,
    only_available: bool,
    total_output_count: &mut usize,
    max_output_count: usize,
) -> usize {
    if batch.is_empty() || *total_output_count >= max_output_count {
        return 0;
    }

    let mut batch_output_count = 0;
    let remaining_output_slots = max_output_count - *total_output_count;
    let batch_to_process: Vec<(String, SimilarityScore)> =
        batch.drain(..).take(remaining_output_slots).collect();

    if check_status {
        // Extract domains for checking
        let domains_to_check: Vec<String> = batch_to_process
            .iter()
            .map(|(domain, _)| domain.clone())
            .collect();

        if !domains_to_check.is_empty() {
            // Use concurrent domain checking with reasonable concurrency limit
            let concurrency = 15; // Good balance between speed and not overwhelming servers
            let results = check_domains_concurrent(domains_to_check, concurrency).await;

            // Process results and apply filters
            for (domain, status) in results {
                let should_show = if only_registered {
                    status != "available"
                } else if only_available {
                    status == "available"
                } else {
                    true // Show all domains with status
                };

                if should_show && batch_output_count < remaining_output_slots {
                    // Find similarity score for this domain
                    if let Some((_, score)) = batch_to_process.iter().find(|(d, _)| d == &domain) {
                        println!(
                            "{:.2}%, {}, combo, {}",
                            score.combined_score * 100.0,
                            domain,
                            status
                        );
                    } else {
                        println!("0.00%, {}, combo, {}", domain, status);
                    }
                    batch_output_count += 1;
                }
            }
        }
    } else {
        // Output without status checking
        for (domain, score) in batch_to_process.iter().take(remaining_output_slots) {
            println!("{:.2}%, {}, combo", score.combined_score * 100.0, domain);
            batch_output_count += 1;
        }
    }

    *total_output_count += batch_output_count;
    batch_output_count
}

fn parse_domain(input: &str) -> (String, String) {
    if let Some(dot_pos) = input.rfind('.') {
        let (domain_part, tld_part) = input.split_at(dot_pos);
        let domain = domain_part.to_string();
        let tld = tld_part.trim_start_matches('.').to_string();
        (domain, tld)
    } else {
        (input.to_string(), "com".to_string())
    }
}

fn extract_registrable_domain(input: &str) -> String {
    // For domains with subdomains like "con.cordiumm.com", extract "cordiumm.com"
    let parts: Vec<&str> = input.split('.').collect();

    if parts.len() >= 2 {
        // Take the last two parts (domain + TLD)
        let domain = parts[parts.len() - 2];
        let tld = parts[parts.len() - 1];
        format!("{}.{}", domain, tld)
    } else {
        // If somehow there's no dot, return as-is
        input.to_string()
    }
}

fn generate_1337speak(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Work with lowercase for consistent matching
    let domain_lower = domain.to_lowercase();
    let chars: Vec<char> = domain_lower.chars().collect();

    if chars.is_empty() {
        return variations;
    }

    let substitutions = [
        ('o', '0'),
        ('0', 'o'),
        ('l', '1'),
        ('1', 'l'),
        ('i', '1'),
        ('1', 'i'),
        ('e', '3'),
        ('3', 'e'),
        ('a', '@'),
        ('@', 'a'),
        ('a', '4'),
        ('4', 'a'),
        ('s', '$'),
        ('$', 's'),
        ('s', '5'),
        ('5', 's'),
        ('g', '9'),
        ('9', 'g'),
        ('b', '6'),
        ('6', 'b'),
        ('t', '7'),
        ('7', 't'),
        ('z', '2'),
        ('2', 'z'),
        ('i', 'l'),
        ('l', 'i'),
        ('o', 'q'),
        ('q', 'o'),
        ('p', 'q'),
        ('q', 'p'),
        ('d', 'b'),
        ('b', 'd'),
        ('u', 'v'),
        ('v', 'u'),
        ('m', 'n'),
        ('n', 'm'),
        ('r', 'n'),
        ('h', 'n'),
    ];

    // Build character errors for each position
    let mut character_errors = Vec::new();
    for (pos, &ch) in chars.iter().enumerate() {
        let mut pos_errors = Vec::new();

        // Find all possible 1337speak substitutions for this character
        for &(from, to) in &substitutions {
            if from == ch {
                pos_errors.push((pos, "substitute", to));
            }
        }

        if !pos_errors.is_empty() {
            character_errors.push(pos_errors);
        }
    }

    if character_errors.is_empty() {
        return variations;
    }

    // Apply realistic constraints similar to fat-finger
    let max_errors = ((chars.len() as f32 * 0.4).ceil() as usize).clamp(1, 3);
    let max_length = (domain_lower.len() as f32 * 1.2) as usize; // 1337speak doesn't typically increase length much

    generate_realistic_combinations(
        &chars,
        &character_errors,
        max_errors,
        max_length,
        tld,
        &mut variations,
    );

    variations
}

fn generate_cognitive(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Cognitive/semantic word confusion transformations
    // Based on lexical similarity, phonetic similarity, and common business terminology confusion

    // Dictionary of common word confusions for business/tech domains
    let word_confusions = [
        // Spelling variations and common misspellings
        ("amazon", vec!["amazom", "amazone", "amazn"]),
        ("google", vec!["gogle", "googel", "googlle"]),
        ("microsoft", vec!["mircosoft", "microsooft", "microsft"]),
        ("facebook", vec!["facbook", "facebok", "faceboook"]),
        ("paypal", vec!["payball", "paypall", "paypaul"]),
        ("apple", vec!["aple", "applle", "aplle"]),
        ("twitter", vec!["twiter", "twittr", "twittter"]),
        ("linkedin", vec!["linkdin", "linkin", "linkedinn"]),
        // Phonetic and semantic confusion
        ("secure", vec!["secur", "securee", "secuure"]),
        ("support", vec!["suport", "supportt", "supp0rt"]),
        ("service", vec!["servic", "servicee", "servise"]),
        ("account", vec!["acount", "accont", "accountt"]),
        ("login", vec!["loginn", "log1n", "l0gin"]),
        ("portal", vec!["portall", "p0rtal", "porttal"]),
        ("center", vec!["centre", "centr", "centerr"]),
        ("office", vec!["offic", "officee", "0ffice"]),
        // Business terminology confusion
        ("corp", vec!["corporate", "company", "inc"]),
        ("inc", vec!["incorporated", "corp", "company"]),
        ("company", vec!["corp", "inc", "co"]),
        ("group", vec!["grp", "groupe", "groupp"]),
        ("tech", vec!["technology", "tec", "techno"]),
        ("solutions", vec!["solution", "solve", "solutionz"]),
        ("systems", vec!["system", "sys", "systemz"]),
        ("services", vec!["service", "servs", "servicez"]),
        // Common domain confusions (sophisticated transformations like concordium->consordium)
        ("concordium", vec!["consordium", "consortium", "concardium"]),
        ("consortium", vec!["consordium", "concordium", "consortum"]),
        ("foundation", vec!["fundation", "foundtion", "foundaton"]),
        ("enterprise", vec!["enterprize", "enterpise", "enterpris"]),
        (
            "international",
            vec!["internacional", "internation", "intl"],
        ),
        ("development", vec!["developement", "developmnt", "develop"]),
        ("management", vec!["managment", "managem", "manage"]),
        ("consulting", vec!["consultng", "consult", "consultancy"]),
        ("financial", vec!["finance", "finacial", "financ"]),
        ("research", vec!["reserch", "researh", "resarch"]),
        ("laboratory", vec!["lab", "laborat", "laboratry"]),
        ("institute", vec!["institut", "institu", "instit"]),
        ("university", vec!["univrsity", "univ", "universty"]),
        ("college", vec!["colege", "coleg", "collegee"]),
        ("academy", vec!["acadmy", "academ", "academie"]),
        ("network", vec!["netwrk", "net", "nework"]),
        ("security", vec!["securty", "sec", "securit"]),
        ("technology", vec!["technlogy", "tech", "tecnology"]),
        ("innovation", vec!["inovation", "innov", "innovaton"]),
        ("intelligence", vec!["inteligence", "intel", "intelligenc"]),
        ("analytics", vec!["analytic", "anlytics", "analytix"]),
        (
            "communications",
            vec!["communication", "comm", "comunications"],
        ),
    ];

    // Apply word confusion transformations
    for &(original_word, ref confusions) in &word_confusions {
        if domain.to_lowercase().contains(original_word) {
            for confusion in confusions {
                let confused_domain = domain.to_lowercase().replace(original_word, confusion);
                if confused_domain != domain.to_lowercase() {
                    variations.push(format!("{}.{}", confused_domain, tld));
                }
            }
        }
    }

    // Reverse lookup - check if domain contains any confusion words
    for &(original_word, ref confusions) in &word_confusions {
        for confusion in confusions {
            if domain.to_lowercase().contains(confusion) {
                let corrected_domain = domain.to_lowercase().replace(confusion, original_word);
                if corrected_domain != domain.to_lowercase() {
                    variations.push(format!("{}.{}", corrected_domain, tld));
                }
            }
        }
    }

    // Phonetic similarity transformations (sounds-like transformations)
    let phonetic_substitutions = [
        ("ph", "f"),
        ("f", "ph"),
        ("ck", "k"),
        ("k", "ck"),
        ("c", "k"),
        ("k", "c"),
        ("s", "z"),
        ("z", "s"),
        ("i", "y"),
        ("y", "i"),
        ("er", "or"),
        ("or", "er"),
        ("an", "en"),
        ("en", "an"),
        ("tion", "sion"),
        ("sion", "tion"),
    ];

    for &(from, to) in &phonetic_substitutions {
        if domain.contains(from) {
            let phonetic_variant = domain.replace(from, to);
            if phonetic_variant != domain {
                variations.push(format!("{}.{}", phonetic_variant, tld));
            }
        }
    }

    // Compound word separation transformations
    let common_compounds = [
        "facebook",
        "youtube",
        "linkedin",
        "instagram",
        "microsoft",
        "paypal",
        "amazon",
        "google",
        "twitter",
        "whatsapp",
        "airbnb",
        "spotify",
        "netflix",
        "dropbox",
        "github",
    ];

    for compound in &common_compounds {
        if domain.to_lowercase().contains(compound) {
            // Try to split compound words intelligently
            match *compound {
                "facebook" => {
                    variations.push(format!(
                        "{}.{}",
                        domain.to_lowercase().replace("facebook", "face-book"),
                        tld
                    ));
                    variations.push(format!(
                        "{}.{}",
                        domain.to_lowercase().replace("facebook", "faceb00k"),
                        tld
                    ));
                }
                "youtube" => {
                    variations.push(format!(
                        "{}.{}",
                        domain.to_lowercase().replace("youtube", "you-tube"),
                        tld
                    ));
                    variations.push(format!(
                        "{}.{}",
                        domain.to_lowercase().replace("youtube", "youtub3"),
                        tld
                    ));
                }
                "linkedin" => {
                    variations.push(format!(
                        "{}.{}",
                        domain.to_lowercase().replace("linkedin", "linked-in"),
                        tld
                    ));
                    variations.push(format!(
                        "{}.{}",
                        domain.to_lowercase().replace("linkedin", "link3din"),
                        tld
                    ));
                }
                "instagram" => {
                    variations.push(format!(
                        "{}.{}",
                        domain.to_lowercase().replace("instagram", "insta-gram"),
                        tld
                    ));
                    variations.push(format!(
                        "{}.{}",
                        domain.to_lowercase().replace("instagram", "instagr4m"),
                        tld
                    ));
                }
                "microsoft" => {
                    variations.push(format!(
                        "{}.{}",
                        domain.to_lowercase().replace("microsoft", "micro-soft"),
                        tld
                    ));
                    variations.push(format!(
                        "{}.{}",
                        domain.to_lowercase().replace("microsoft", "micr0soft"),
                        tld
                    ));
                }
                _ => {}
            }
        }
    }

    // Business context confusion (authority terms)
    let business_contexts = [
        ("bank", vec!["banking", "banc", "finansial"]),
        ("pay", vec!["payment", "payments", "paying"]),
        ("shop", vec!["shopping", "store", "market"]),
        ("mail", vec!["email", "post", "message"]),
        ("cloud", vec!["server", "hosting", "storage"]),
        ("data", vec!["database", "info", "information"]),
        ("web", vec!["website", "site", "online"]),
        ("mobile", vec!["app", "application", "phone"]),
        ("digital", vec!["cyber", "online", "virtual"]),
        ("crypto", vec!["blockchain", "bitcoin", "coin"]),
    ];

    for &(context_word, ref alternatives) in &business_contexts {
        if domain.to_lowercase().contains(context_word) {
            for alt in alternatives {
                let contextual_variant = domain.to_lowercase().replace(context_word, alt);
                if contextual_variant != domain.to_lowercase() {
                    variations.push(format!("{}.{}", contextual_variant, tld));
                }
            }
        }
    }

    // Remove duplicates and original domain
    variations.sort();
    variations.dedup();
    variations.retain(|v| v != &format!("{}.{}", domain, tld));

    variations
}

fn generate_mixed_encodings(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    let domain_lower = domain.to_lowercase();
    let chars: Vec<char> = domain_lower.chars().collect();

    // Comprehensive encoding map (homoglyphs, IDN, mixed-script, extended unicode, cyrillic)
    let encoding_map: std::collections::HashMap<char, Vec<char>> = [
        ('a', vec!['а', 'α', 'ａ']), // Cyrillic а, Greek α, Fullwidth a
        ('e', vec!['е', 'ε', 'ｅ']), // Cyrillic е, Greek ε, Fullwidth e
        ('o', vec!['о', 'ο', 'ｏ']), // Cyrillic о, Greek ο, Fullwidth o
        ('p', vec!['р', 'ρ', 'ｐ']), // Cyrillic р, Greek ρ, Fullwidth p
        ('c', vec!['с', 'ｃ']),      // Cyrillic с, Fullwidth c
        ('y', vec!['у', 'ｙ']),      // Cyrillic у, Fullwidth y
        ('x', vec!['х', 'χ', 'ｘ']), // Cyrillic х, Greek χ, Fullwidth x
        ('v', vec!['ν', 'ｖ']),      // Greek ν, Fullwidth v
        ('u', vec!['υ', 'ｕ']),      // Greek υ, Fullwidth u
        ('i', vec!['і', 'ι', 'ｉ']), // Cyrillic і, Greek ι, Fullwidth i
        ('j', vec!['ј', 'ｊ']),      // Cyrillic ј, Fullwidth j
        ('s', vec!['ѕ', 'ｓ']),      // Cyrillic ѕ, Fullwidth s
        ('b', vec!['ь', 'β', 'ｂ']), // Cyrillic ь, Greek β, Fullwidth b
        ('h', vec!['н', 'η', 'ｈ']), // Cyrillic н, Greek η, Fullwidth h
        ('k', vec!['к', 'κ', 'ｋ']), // Cyrillic к, Greek κ, Fullwidth k
        ('m', vec!['м', 'μ', 'ｍ']), // Cyrillic м, Greek μ, Fullwidth m
        ('n', vec!['п', 'η', 'ｎ']), // Cyrillic п, Greek η, Fullwidth n
        ('t', vec!['т', 'τ', 'ｔ']), // Cyrillic т, Greek τ, Fullwidth t
        ('r', vec!['г', 'ρ', 'ｒ']), // Cyrillic г, Greek ρ, Fullwidth r
        ('d', vec!['д', 'ｄ']),      // Cyrillic д, Fullwidth d
        ('f', vec!['ф', 'ｆ']),      // Cyrillic ф, Fullwidth f
        ('g', vec!['ѓ', 'ｇ']),      // Cyrillic ѓ, Fullwidth g
        ('l', vec!['ӏ', 'ｌ']),      // Cyrillic ӏ, Fullwidth l
        ('w', vec!['ѡ', 'ｗ']),      // Cyrillic ѡ, Fullwidth w
        ('q', vec!['ԛ', 'ｑ']),      // Cyrillic ԛ, Fullwidth q
        ('z', vec!['ᴢ', 'ｚ']),      // Small capital Z, Fullwidth z
    ]
    .iter()
    .cloned()
    .collect();

    // Calculate realistic constraints for Unicode substitutions
    let max_errors = ((chars.len() as f32 * 0.6).ceil() as usize).max(1); // Up to 60% of chars can be Unicode
    let max_length = domain.len(); // Unicode substitutions don't change length

    // Find all character positions where encoding substitutions can occur
    let mut character_encodings = Vec::new();

    for (pos, &ch) in chars.iter().enumerate() {
        if let Some(encoding_chars) = encoding_map.get(&ch) {
            let mut pos_encodings = Vec::new();
            for &encoding_char in encoding_chars {
                pos_encodings.push((pos, "unicode_sub", encoding_char));
            }
            if !pos_encodings.is_empty() {
                character_encodings.push(pos_encodings);
            }
        }
    }

    // Generate realistic encoding combinations
    generate_encoding_combinations(
        &chars,
        &character_encodings,
        max_errors,
        max_length,
        tld,
        &mut variations,
    );

    variations
}

fn generate_encoding_combinations(
    original_chars: &[char],
    character_encodings: &[Vec<(usize, &str, char)>],
    max_errors: usize,
    _max_length: usize,
    tld: &str,
    variations: &mut Vec<String>,
) {
    let domain: String = original_chars.iter().collect();

    // Generate single encoding substitutions first (most common)
    for pos_encodings in character_encodings {
        for &(pos, _error_type, replacement) in pos_encodings {
            let result = apply_single_encoding(original_chars, pos, replacement);
            if let Some(result_domain) = result {
                if result_domain != domain {
                    variations.push(format!("{}.{}", result_domain, tld));
                }
            }
        }
    }

    // Generate double encoding substitutions for longer domains (length >= 3)
    if original_chars.len() >= 3 && max_errors >= 2 {
        for i in 0..character_encodings.len() {
            for j in (i + 1)..character_encodings.len() {
                // For Unicode, allow any spacing between substitutions
                // Take only first few encoding options to prevent explosion
                for &(pos1, _error_type1, replacement1) in character_encodings[i].iter().take(2) {
                    for &(pos2, _error_type2, replacement2) in character_encodings[j].iter().take(2)
                    {
                        let result = apply_double_encoding(
                            original_chars,
                            pos1,
                            replacement1,
                            pos2,
                            replacement2,
                        );
                        if let Some(result_domain) = result {
                            if result_domain != domain {
                                variations.push(format!("{}.{}", result_domain, tld));
                            }
                        }
                    }
                }
            }
        }
    }

    // Generate triple encoding substitutions for longer domains (length >= 5)
    if original_chars.len() >= 5 && max_errors >= 3 {
        for i in 0..character_encodings.len() {
            for j in (i + 2)..character_encodings.len() {
                for k in (j + 2)..character_encodings.len() {
                    // Very selective sampling for triple encodings
                    for &(pos1, _error_type1, replacement1) in character_encodings[i].iter().take(1)
                    {
                        for &(pos2, _error_type2, replacement2) in
                            character_encodings[j].iter().take(1)
                        {
                            for &(pos3, _error_type3, replacement3) in
                                character_encodings[k].iter().take(1)
                            {
                                let result = apply_triple_encoding(
                                    original_chars,
                                    pos1,
                                    replacement1,
                                    pos2,
                                    replacement2,
                                    pos3,
                                    replacement3,
                                );
                                if let Some(result_domain) = result {
                                    if result_domain != domain {
                                        variations.push(format!("{}.{}", result_domain, tld));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn apply_single_encoding(chars: &[char], pos: usize, replacement: char) -> Option<String> {
    if pos >= chars.len() {
        return None;
    }

    let mut result_chars = chars.to_vec();
    result_chars[pos] = replacement;
    Some(result_chars.iter().collect())
}

fn apply_double_encoding(
    chars: &[char],
    pos1: usize,
    replacement1: char,
    pos2: usize,
    replacement2: char,
) -> Option<String> {
    if pos1 >= chars.len() || pos2 >= chars.len() {
        return None;
    }

    let mut result_chars = chars.to_vec();
    result_chars[pos1] = replacement1;
    result_chars[pos2] = replacement2;
    Some(result_chars.iter().collect())
}

fn apply_triple_encoding(
    chars: &[char],
    pos1: usize,
    replacement1: char,
    pos2: usize,
    replacement2: char,
    pos3: usize,
    replacement3: char,
) -> Option<String> {
    if pos1 >= chars.len() || pos2 >= chars.len() || pos3 >= chars.len() {
        return None;
    }

    let mut result_chars = chars.to_vec();
    result_chars[pos1] = replacement1;
    result_chars[pos2] = replacement2;
    result_chars[pos3] = replacement3;
    Some(result_chars.iter().collect())
}

fn generate_misspelling(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    let chars: Vec<char> = domain.chars().collect();

    // QWERTY keyboard map for adjacent keys
    let qwerty_map = [
        ('q', "wa"),
        ('w', "qes"),
        ('e', "wrd"),
        ('r', "etf"),
        ('t', "rgy"),
        ('y', "tuh"),
        ('u', "yio"),
        ('i', "uop"),
        ('o', "ip"),
        ('p', "o"),
        ('a', "qsz"),
        ('s', "awdz"),
        ('d', "sefx"),
        ('f', "dgrc"),
        ('g', "fthv"),
        ('h', "gyjb"),
        ('j', "hukn"),
        ('k', "julm"),
        ('l', "km"),
        ('z', "asx"),
        ('x', "zsdc"),
        ('c', "xdfv"),
        ('v', "cfgb"),
        ('b', "vghn"),
        ('n', "bhjm"),
        ('m', "njk"),
    ];

    // Vowel substitution mappings from vowel-swap
    let vowel_swap_map: std::collections::HashMap<char, Vec<char>> = [
        ('a', vec!['e', 'i', 'o', 'u']),
        ('e', vec!['a', 'i', 'o', 'u']),
        ('i', vec!['a', 'e', 'o', 'u']),
        ('o', vec!['a', 'e', 'i', 'u']),
        ('u', vec!['a', 'e', 'i', 'o']),
    ]
    .iter()
    .cloned()
    .collect();

    // Calculate realistic constraints based on domain length
    let max_errors = (chars.len() / 2).max(1); // 1 error per 2 characters, minimum 1
    let max_length = (domain.len() as f32 * 1.8) as usize; // Max 180% of original length (more lenient than fat-finger)

    // Find all character positions where misspelling errors can occur
    let mut character_errors = Vec::new();

    for (pos, &ch) in chars.iter().enumerate() {
        let mut pos_errors = Vec::new();

        // Character insertion (add random char before this position)
        pos_errors.push((pos, "insert", 'a')); // Representative insertion

        // Character deletion
        pos_errors.push((pos, "delete", ch));

        // Character transposition (with next character)
        if pos + 1 < chars.len() {
            pos_errors.push((pos, "transpose", chars[pos + 1]));
        }

        // Keyboard adjacent substitution
        let lower_ch = ch.to_ascii_lowercase();
        for (orig_char, adjacent_chars) in &qwerty_map {
            if lower_ch == *orig_char {
                for adj_char in adjacent_chars.chars() {
                    pos_errors.push((pos, "keyboard_sub", adj_char));
                }
                break;
            }
        }

        // Vowel substitution
        if let Some(vowel_substitutes) = vowel_swap_map.get(&lower_ch) {
            for &substitute_vowel in vowel_substitutes {
                let final_vowel = if ch.is_uppercase() {
                    substitute_vowel.to_ascii_uppercase()
                } else {
                    substitute_vowel
                };
                pos_errors.push((pos, "vowel_sub", final_vowel));
            }
        }

        if !pos_errors.is_empty() {
            character_errors.push(pos_errors);
        }
    }

    // Generate realistic combinations with constraints
    generate_misspelling_combinations(
        &chars,
        &character_errors,
        max_errors,
        max_length,
        tld,
        &mut variations,
    );

    variations
}

fn generate_misspelling_combinations(
    original_chars: &[char],
    character_errors: &[Vec<(usize, &str, char)>],
    max_errors: usize,
    max_length: usize,
    tld: &str,
    variations: &mut Vec<String>,
) {
    let domain: String = original_chars.iter().collect();

    // Generate single misspelling errors first (most realistic)
    for pos_errors in character_errors {
        for &(pos, error_type, replacement) in pos_errors {
            let result = apply_single_misspelling(original_chars, pos, error_type, replacement);
            if let Some(result_domain) = result {
                if result_domain != domain
                    && result_domain.len() <= max_length
                    && !result_domain.is_empty()
                {
                    variations.push(format!("{}.{}", result_domain, tld));
                }
            }
        }
    }

    // Generate double misspellings for longer domains (length >= 4)
    if original_chars.len() >= 4 && max_errors >= 2 {
        for i in 0..character_errors.len() {
            for j in (i + 1)..character_errors.len() {
                // Allow errors on adjacent characters for misspellings (unlike fat-finger)
                // But limit combinations to avoid explosion
                if j - i <= 2 {
                    // Only adjacent or 1-apart characters
                    for &(pos1, error_type1, replacement1) in character_errors[i].iter().take(2) {
                        for &(pos2, error_type2, replacement2) in character_errors[j].iter().take(2)
                        {
                            // Avoid incompatible error combinations
                            if !are_incompatible_misspelling_errors(
                                pos1,
                                error_type1,
                                pos2,
                                error_type2,
                            ) {
                                let result = apply_double_misspelling(
                                    original_chars,
                                    pos1,
                                    error_type1,
                                    replacement1,
                                    pos2,
                                    error_type2,
                                    replacement2,
                                );
                                if let Some(result_domain) = result {
                                    if result_domain != domain
                                        && result_domain.len() <= max_length
                                        && !result_domain.is_empty()
                                    {
                                        variations.push(format!("{}.{}", result_domain, tld));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn are_incompatible_misspelling_errors(pos1: usize, type1: &str, pos2: usize, type2: &str) -> bool {
    // Don't delete adjacent characters (would create too many gaps)
    if (type1 == "delete" && type2 == "delete") && (pos2 == pos1 + 1 || pos1 == pos2 + 1) {
        return true;
    }

    // Don't transpose overlapping ranges
    if type1 == "transpose" && type2 == "transpose" && (pos2 <= pos1 + 1) {
        return true;
    }

    // Don't delete and transpose the same position
    if (type1 == "delete" && type2 == "transpose" && pos1 == pos2)
        || (type2 == "delete" && type1 == "transpose" && pos2 == pos1)
    {
        return true;
    }

    false
}

fn apply_single_misspelling(
    chars: &[char],
    pos: usize,
    error_type: &str,
    replacement: char,
) -> Option<String> {
    let mut result_chars = chars.to_vec();

    match error_type {
        "insert" => {
            // Insert a common typo character
            let typo_chars = ['a', 'e', 'i', 'o', 'u', 's', 't', 'n', 'r'];
            let typo_char = typo_chars[pos % typo_chars.len()];
            result_chars.insert(pos, typo_char);
        }
        "delete" => {
            if pos < result_chars.len() {
                result_chars.remove(pos);
            }
        }
        "transpose" => {
            if pos + 1 < result_chars.len() {
                result_chars.swap(pos, pos + 1);
            }
        }
        "keyboard_sub" => {
            if pos < result_chars.len() {
                result_chars[pos] = if chars[pos].is_uppercase() {
                    replacement.to_ascii_uppercase()
                } else {
                    replacement
                };
            }
        }
        "vowel_sub" => {
            if pos < result_chars.len() {
                result_chars[pos] = replacement;
            }
        }
        _ => return None,
    }

    if result_chars.is_empty() {
        return None;
    }

    Some(result_chars.iter().collect())
}

fn apply_double_misspelling(
    chars: &[char],
    pos1: usize,
    error_type1: &str,
    replacement1: char,
    pos2: usize,
    error_type2: &str,
    replacement2: char,
) -> Option<String> {
    // Apply first error
    let intermediate = apply_single_misspelling(chars, pos1, error_type1, replacement1)?;
    let intermediate_chars: Vec<char> = intermediate.chars().collect();

    // Adjust position for second error based on first error's effect
    let adjusted_pos2 = match error_type1 {
        "insert" => {
            if pos2 > pos1 {
                pos2 + 1
            } else {
                pos2
            }
        }
        "delete" => {
            if pos2 > pos1 && pos2 > 0 {
                pos2 - 1
            } else {
                pos2
            }
        }
        _ => pos2,
    };

    // Apply second error
    apply_single_misspelling(
        &intermediate_chars,
        adjusted_pos2,
        error_type2,
        replacement2,
    )
}

fn generate_subdomain_injection(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    let chars: Vec<char> = domain.chars().collect();
    for i in 1..chars.len() {
        // Skip positions that would create consecutive dots
        if i > 0 && chars[i - 1] == '.' {
            continue;
        }
        if i < chars.len() && chars[i] == '.' {
            continue;
        }

        // Convert char index to byte index for insertion
        let byte_pos = domain
            .char_indices()
            .nth(i)
            .map(|(pos, _)| pos)
            .unwrap_or(domain.len());
        let mut new_domain = domain.to_string();
        new_domain.insert(byte_pos, '.');
        variations.push(format!("{}.{}", new_domain, tld));
    }

    variations
}

fn generate_tld_variations(domain: &str, _tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    let tlds = [
        "com", "net", "org", "info", "biz", "us", "co", "io", "me", "app", "dev", "tech", "online",
        "site", "store", "shop", "uk", "ca", "de", "fr", "ru", "cn", "jp", "au", "br", "tk", "ml",
        "ga", "cf",
    ];

    for &new_tld in &tlds {
        variations.push(format!("{}.{}", domain, new_tld));
    }

    variations
}

fn generate_word_swaps(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    let chars: Vec<char> = domain.chars().collect();

    if chars.len() >= 4 {
        let mid = chars.len() / 2;
        let first_half: String = chars[..mid].iter().collect();
        let second_half: String = chars[mid..].iter().collect();
        variations.push(format!("{}{}.{}", second_half, first_half, tld));
    }

    if chars.len() >= 6 {
        let third = chars.len() / 3;
        let first_third: String = chars[..third].iter().collect();
        let middle_third: String = chars[third..2 * third].iter().collect();
        let last_third: String = chars[2 * third..].iter().collect();
        variations.push(format!(
            "{}{}{}.{}",
            last_third, middle_third, first_third, tld
        ));
    }

    variations
}

fn generate_bitsquatting(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    let chars: Vec<char> = domain.chars().collect();

    for (i, &ch) in chars.iter().enumerate() {
        let ch_code = ch as u8;
        for bit_pos in 0..8 {
            let flipped_code = ch_code ^ (1 << bit_pos);
            if let Some(flipped_char) = char::from_u32(flipped_code as u32) {
                if flipped_char.is_ascii_alphabetic() || flipped_char.is_ascii_digit() {
                    let mut new_domain = String::new();
                    new_domain.push_str(&chars[..i].iter().collect::<String>());
                    new_domain.push(flipped_char);
                    new_domain.push_str(&chars[i + 1..].iter().collect::<String>());
                    variations.push(format!("{}.{}", new_domain, tld));
                }
            }
        }
    }

    variations
}

fn generate_fat_finger(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    let chars: Vec<char> = domain.chars().collect();

    // QWERTY keyboard map for adjacent keys
    let qwerty_map = [
        ('q', "wa"),
        ('w', "qes"),
        ('e', "wrd"),
        ('r', "etf"),
        ('t', "rgy"),
        ('y', "tuh"),
        ('u', "yio"),
        ('i', "uop"),
        ('o', "ip"),
        ('p', "o"),
        ('a', "qsz"),
        ('s', "awdz"),
        ('d', "sefx"),
        ('f', "dgrc"),
        ('g', "fthv"),
        ('h', "gyjb"),
        ('j', "hukn"),
        ('k', "julm"),
        ('l', "km"),
        ('z', "asx"),
        ('x', "zsdc"),
        ('c', "xdfv"),
        ('v', "cfgb"),
        ('b', "vghn"),
        ('n', "bhjm"),
        ('m', "njk"),
    ];

    // Calculate realistic constraints based on domain length
    let max_errors = (chars.len() / 2).max(1); // 1 error per 2 characters, minimum 1
    let max_length = (domain.len() as f32 * 1.5) as usize; // Max 150% of original length

    // Find all character positions where errors can occur (max 1 error type per position)
    let mut character_errors = Vec::new();

    for (pos, &ch) in chars.iter().enumerate() {
        let mut pos_errors = Vec::new();

        // Character repetition
        pos_errors.push((pos, "repeat", ch));

        // Adjacent key substitution
        for (orig_char, adjacent_chars) in &qwerty_map {
            if ch == *orig_char {
                for adj_char in adjacent_chars.chars() {
                    pos_errors.push((pos, "substitute", adj_char));
                }
                break; // Only one set of adjacent keys per character
            }
        }

        // Adjacent key insertion (before this character)
        for (orig_char, adjacent_chars) in &qwerty_map {
            if ch == *orig_char {
                for adj_char in adjacent_chars.chars() {
                    pos_errors.push((pos, "insert_before", adj_char));
                }
                break;
            }
        }

        if !pos_errors.is_empty() {
            character_errors.push(pos_errors);
        }
    }

    // Generate realistic combinations with constraints
    generate_realistic_combinations(
        &chars,
        &character_errors,
        max_errors,
        max_length,
        tld,
        &mut variations,
    );

    variations
}

fn generate_realistic_combinations(
    original_chars: &[char],
    character_errors: &[Vec<(usize, &str, char)>],
    max_errors: usize,
    max_length: usize,
    tld: &str,
    variations: &mut Vec<String>,
) {
    let domain: String = original_chars.iter().collect();

    // Generate single errors first (most realistic)
    for pos_errors in character_errors {
        for &(pos, error_type, replacement) in pos_errors {
            let result = apply_single_error(original_chars, pos, error_type, replacement);
            if let Some(result_domain) = result {
                if result_domain != domain && result_domain.len() <= max_length {
                    variations.push(format!("{}.{}", result_domain, tld));
                }
            }
        }
    }

    // Generate double errors for longer domains (length >= 4)
    if original_chars.len() >= 4 && max_errors >= 2 {
        for i in 0..character_errors.len() {
            for j in (i + 1)..character_errors.len() {
                // Only allow errors on non-adjacent characters for realism
                if j - i > 1 {
                    for &(pos1, error_type1, replacement1) in &character_errors[i] {
                        for &(pos2, error_type2, replacement2) in &character_errors[j] {
                            let result = apply_double_error(
                                original_chars,
                                pos1,
                                error_type1,
                                replacement1,
                                pos2,
                                error_type2,
                                replacement2,
                            );
                            if let Some(result_domain) = result {
                                if result_domain != domain && result_domain.len() <= max_length {
                                    variations.push(format!("{}.{}", result_domain, tld));
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Only generate triple errors for very long domains (length >= 8)
    if original_chars.len() >= 8 && max_errors >= 3 {
        for i in 0..character_errors.len() {
            for j in (i + 2)..character_errors.len() {
                for k in (j + 2)..character_errors.len() {
                    // Sample only a few triple combinations to avoid explosion
                    if i % 2 == 0 && j % 2 == 0 && k % 2 == 0 {
                        for &(pos1, error_type1, replacement1) in character_errors[i].iter().take(1)
                        {
                            for &(pos2, error_type2, replacement2) in
                                character_errors[j].iter().take(1)
                            {
                                for &(pos3, error_type3, replacement3) in
                                    character_errors[k].iter().take(1)
                                {
                                    let error1 = ErrorSpec {
                                        pos: pos1,
                                        error_type: error_type1.to_string(),
                                        replacement: replacement1,
                                    };
                                    let error2 = ErrorSpec {
                                        pos: pos2,
                                        error_type: error_type2.to_string(),
                                        replacement: replacement2,
                                    };
                                    let error3 = ErrorSpec {
                                        pos: pos3,
                                        error_type: error_type3.to_string(),
                                        replacement: replacement3,
                                    };
                                    let result = apply_triple_error(
                                        original_chars,
                                        &error1,
                                        &error2,
                                        &error3,
                                    );
                                    if let Some(result_domain) = result {
                                        if result_domain != domain
                                            && result_domain.len() <= max_length
                                        {
                                            variations.push(format!("{}.{}", result_domain, tld));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn apply_single_error(
    chars: &[char],
    pos: usize,
    error_type: &str,
    replacement: char,
) -> Option<String> {
    let mut result_chars = chars.to_vec();

    match error_type {
        "repeat" => {
            if pos < result_chars.len() {
                result_chars.insert(pos, replacement);
            }
        }
        "substitute" => {
            if pos < result_chars.len() {
                result_chars[pos] = replacement;
            }
        }
        "insert_before" => {
            result_chars.insert(pos, replacement);
        }
        _ => return None,
    }

    Some(result_chars.iter().collect())
}

fn apply_double_error(
    chars: &[char],
    pos1: usize,
    error_type1: &str,
    replacement1: char,
    pos2: usize,
    error_type2: &str,
    replacement2: char,
) -> Option<String> {
    let mut result_chars = chars.to_vec();

    // Apply errors in reverse position order to maintain indices
    let (first_pos, first_type, first_repl, second_pos, second_type, second_repl) = if pos2 > pos1 {
        (
            pos1,
            error_type1,
            replacement1,
            pos2,
            error_type2,
            replacement2,
        )
    } else {
        (
            pos2,
            error_type2,
            replacement2,
            pos1,
            error_type1,
            replacement1,
        )
    };

    // Apply second error first (higher position)
    match second_type {
        "repeat" => {
            if second_pos < result_chars.len() {
                result_chars.insert(second_pos, second_repl);
            }
        }
        "substitute" => {
            if second_pos < result_chars.len() {
                result_chars[second_pos] = second_repl;
            }
        }
        "insert_before" => {
            result_chars.insert(second_pos, second_repl);
        }
        _ => return None,
    }

    // Apply first error
    match first_type {
        "repeat" => {
            if first_pos < result_chars.len() {
                result_chars.insert(first_pos, first_repl);
            }
        }
        "substitute" => {
            if first_pos < result_chars.len() {
                result_chars[first_pos] = first_repl;
            }
        }
        "insert_before" => {
            result_chars.insert(first_pos, first_repl);
        }
        _ => return None,
    }

    Some(result_chars.iter().collect())
}

#[derive(Clone)]
struct ErrorSpec {
    pos: usize,
    error_type: String,
    replacement: char,
}

fn apply_triple_error(
    chars: &[char],
    error1: &ErrorSpec,
    error2: &ErrorSpec,
    error3: &ErrorSpec,
) -> Option<String> {
    // Apply double error first, then add third error
    let double_result = apply_double_error(
        chars,
        error1.pos,
        &error1.error_type,
        error1.replacement,
        error2.pos,
        &error2.error_type,
        error2.replacement,
    )?;
    let double_chars: Vec<char> = double_result.chars().collect();

    // Adjust position for third error based on insertions from first two errors
    let adjusted_pos3 = if error3.pos > error2.pos && error3.pos > error1.pos {
        error3.pos
            + count_insertions_before(
                error3.pos,
                error1.pos,
                &error1.error_type,
                error2.pos,
                &error2.error_type,
            )
    } else {
        error3.pos
    };

    apply_single_error(
        &double_chars,
        adjusted_pos3,
        &error3.error_type,
        error3.replacement,
    )
}

fn count_insertions_before(
    target_pos: usize,
    pos1: usize,
    type1: &str,
    pos2: usize,
    type2: &str,
) -> usize {
    let mut count = 0;
    if pos1 < target_pos && (type1 == "repeat" || type1 == "insert_before") {
        count += 1;
    }
    if pos2 < target_pos && (type2 == "repeat" || type2 == "insert_before") {
        count += 1;
    }
    count
}

fn load_dictionary(file_path: &str) -> Vec<String> {
    use std::fs;
    fs::read_to_string(file_path)
        .unwrap_or_default()
        .lines()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

fn default_dictionary() -> Vec<String> {
    // Try to load from XDG-compliant user data directory first
    if let Ok(home) = std::env::var("HOME") {
        let xdg_dict_path = format!("{}/.local/share/domfuzz/dictionary.txt", home);
        if std::path::Path::new(&xdg_dict_path).exists() {
            return load_dictionary(&xdg_dict_path);
        }
    }

    // Fall back to built-in dictionary
    vec![
        "support", "secure", "login", "pay", "help", "service", "account", "portal", "center",
        "app", "online", "store", "shop", "mail", "cloud", "data", "mobile", "web", "digital",
        "tech", "pro", "plus", "premium", "official", "admin", "manage", "bank", "finance",
        "crypto",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect()
}

fn generate_combosquatting(domain: &str, tld: &str, dict_words: &[String]) -> Vec<String> {
    let mut variations = Vec::new();

    for word in dict_words {
        variations.push(format!("{}-{}.{}", domain, word, tld));
        variations.push(format!("{}{}.{}", domain, word, tld));
        variations.push(format!("{}-{}.{}", word, domain, tld));
        variations.push(format!("{}{}.{}", word, domain, tld));
    }

    variations
}

fn generate_hyphenation(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    let chars: Vec<char> = domain.chars().collect();
    for i in 1..chars.len() {
        // Skip positions that would create domains starting/ending with hyphens
        // or consecutive hyphens
        if i > 0 && chars[i - 1] == '-' {
            continue;
        }
        if i < chars.len() && chars[i] == '-' {
            continue;
        }

        // Convert char index to byte index for insertion
        let byte_pos = domain
            .char_indices()
            .nth(i)
            .map(|(pos, _)| pos)
            .unwrap_or(domain.len());
        let mut new_domain = domain.to_string();
        new_domain.insert(byte_pos, '-');

        // Additional check: don't create domains ending with hyphen
        if new_domain.ends_with('-') {
            continue;
        }

        variations.push(format!("{}.{}", new_domain, tld));
    }

    variations
}

fn generate_brand_confusion(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    let authority_prefixes = ["www", "secure", "official", "my", "admin", "portal", "app"];
    let authority_suffixes = ["app", "online", "portal", "center", "pro", "plus", "secure"];

    for prefix in &authority_prefixes {
        variations.push(format!("{}-{}.{}", prefix, domain, tld));
        variations.push(format!("{}.{}.{}", prefix, domain, tld));
    }

    for suffix in &authority_suffixes {
        variations.push(format!("{}-{}.{}", domain, suffix, tld));
        variations.push(format!("{}{}.{}", domain, suffix, tld));
    }

    variations
}

fn generate_intl_tld(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    let idn_tlds = [
        ("com", "ком"),
        ("net", "нет"),
        ("org", "орг"),
        ("com", "كوم"),
        ("net", "شبكة"),
        ("org", "منظمة"),
        ("com", "公司"),
        ("net", "网络"),
        ("org", "组织"),
        ("cn", "中国"),
        ("com", "コム"),
        ("net", "ネット"),
        ("org", "オルグ"),
        ("com", "컴"),
        ("net", "넷"),
        ("kr", "한국"),
        ("com", "κομ"),
        ("net", "δικτυο"),
        ("org", "οργ"),
        ("gr", "ελ"),
        ("com", "קום"),
        ("net", "רשת"),
        ("org", "ארג"),
        ("com", "คอม"),
        ("net", "เน็ต"),
        ("th", "ไทย"),
        ("com", "कॉम"),
        ("net", "नेट"),
        ("org", "संगठन"),
        ("in", "भारत"),
    ];

    for &(latin_tld, idn_tld) in &idn_tlds {
        if tld == latin_tld || tld == "com" || tld == "net" || tld == "org" {
            variations.push(format!("{}.{}", domain, idn_tld));
        }
    }

    let mixed_tlds = [
        "co.ук", "com.ау", "со.uk", "сom", "nеt", "оrg", "οrg", "cοm",
    ];

    for mixed_tld in &mixed_tlds {
        variations.push(format!("{}.{}", domain, mixed_tld));
    }

    variations
}

fn generate_dot_insertion(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Insert dots at various positions within the domain (not at start/end)
    let chars: Vec<char> = domain.chars().collect();
    for i in 1..chars.len() {
        // Skip positions that would create consecutive dots
        if i > 0 && chars[i - 1] == '.' {
            continue;
        }
        if i < chars.len() && chars[i] == '.' {
            continue;
        }

        // Convert char index to byte index for insertion
        let byte_pos = domain
            .char_indices()
            .nth(i)
            .map(|(pos, _)| pos)
            .unwrap_or(domain.len());
        let mut new_domain = domain.to_string();
        new_domain.insert(byte_pos, '.');
        variations.push(format!("{}.{}", new_domain, tld));
    }

    variations
}

fn generate_dot_omission(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Remove existing dots from the domain
    if domain.contains('.') {
        let stripped = domain.replace(".", "");
        if !stripped.is_empty() {
            variations.push(format!("{}.{}", stripped, tld));
        }
    }

    variations
}

fn generate_dot_hyphen_substitution(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Replace dots with hyphens
    if domain.contains('.') {
        let hyphenated = domain.replace(".", "-");
        variations.push(format!("{}.{}", hyphenated, tld));
    }

    // Replace hyphens with dots
    if domain.contains('-') {
        let dotted = domain.replace("-", ".");
        variations.push(format!("{}.{}", dotted, tld));
    }

    variations
}

fn generate_cardinal_substitution(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Cardinal number mappings (digit to word and word to digit)
    let cardinals = [
        ("0", "zero"),
        ("1", "one"),
        ("2", "two"),
        ("3", "three"),
        ("4", "four"),
        ("5", "five"),
        ("6", "six"),
        ("7", "seven"),
        ("8", "eight"),
        ("9", "nine"),
        ("10", "ten"),
        ("11", "eleven"),
        ("12", "twelve"),
        ("20", "twenty"),
        ("30", "thirty"),
        ("40", "forty"),
        ("50", "fifty"),
        ("100", "hundred"),
    ];

    // Replace numbers with words
    for &(digit, word) in &cardinals {
        if domain.contains(digit) {
            let word_variant = domain.replace(digit, word);
            if word_variant != domain {
                variations.push(format!("{}.{}", word_variant, tld));
            }
        }

        // Replace words with numbers
        if domain.contains(word) {
            let digit_variant = domain.replace(word, digit);
            if digit_variant != domain {
                variations.push(format!("{}.{}", digit_variant, tld));
            }
        }
    }

    variations
}

fn generate_ordinal_substitution(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Ordinal number mappings
    let ordinals = [
        ("1st", "first"),
        ("2nd", "second"),
        ("3rd", "third"),
        ("4th", "fourth"),
        ("5th", "fifth"),
        ("6th", "sixth"),
        ("7th", "seventh"),
        ("8th", "eighth"),
        ("9th", "ninth"),
        ("10th", "tenth"),
        ("11th", "eleventh"),
        ("12th", "twelfth"),
        ("20th", "twentieth"),
        ("21st", "twentyfirst"),
        ("30th", "thirtieth"),
        ("100th", "hundredth"),
    ];

    // Replace ordinal numbers with words
    for &(ordinal, word) in &ordinals {
        if domain.contains(ordinal) {
            let word_variant = domain.replace(ordinal, word);
            if word_variant != domain {
                variations.push(format!("{}.{}", word_variant, tld));
            }
        }

        // Replace ordinal words with numbers
        if domain.contains(word) {
            let ordinal_variant = domain.replace(word, ordinal);
            if ordinal_variant != domain {
                variations.push(format!("{}.{}", ordinal_variant, tld));
            }
        }
    }

    variations
}

fn generate_homophones(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Common homophones dictionary
    let homophones = [
        ("to", vec!["too", "two"]),
        ("there", vec!["their", "they're"]),
        ("your", vec!["you're"]),
        ("hear", vec!["here"]),
        ("buy", vec!["by", "bye"]),
        ("site", vec!["sight", "cite"]),
        ("right", vec!["write", "rite"]),
        ("four", vec!["for", "fore"]),
        ("one", vec!["won"]),
        ("son", vec!["sun"]),
        ("no", vec!["know"]),
        ("sea", vec!["see"]),
        ("be", vec!["bee"]),
        ("mail", vec!["male"]),
        ("sale", vec!["sail"]),
        ("peace", vec!["piece"]),
        ("break", vec!["brake"]),
        ("cell", vec!["sell"]),
        ("blue", vec!["blew"]),
        ("ate", vec!["eight"]),
        ("week", vec!["weak"]),
        ("meet", vec!["meat"]),
        ("fair", vec!["fare"]),
        ("pair", vec!["pear", "pare"]),
        ("bear", vec!["bare"]),
        ("dear", vec!["deer"]),
        ("flour", vec!["flower"]),
        ("hour", vec!["our"]),
        ("knight", vec!["night"]),
        ("knew", vec!["new"]),
        ("tail", vec!["tale"]),
        ("wait", vec!["weight"]),
        ("way", vec!["weigh"]),
        ("would", vec!["wood"]),
        ("hole", vec!["whole"]),
        ("role", vec!["roll"]),
        ("soul", vec!["sole"]),
        ("steal", vec!["steel"]),
        ("heal", vec!["heel"]),
        ("real", vec!["reel"]),
        ("read", vec!["red"]),
        ("lead", vec!["led"]),
        ("threw", vec!["through"]),
        ("plain", vec!["plane"]),
        ("rain", vec!["reign"]),
        ("main", vec!["mane"]),
        ("pain", vec!["pane"]),
        ("vain", vec!["vane"]),
    ];

    // Apply homophone transformations
    for &(original, ref replacements) in &homophones {
        if domain.to_lowercase().contains(original) {
            for replacement in replacements {
                let variant = domain.to_lowercase().replace(original, replacement);
                if variant != domain.to_lowercase() {
                    variations.push(format!("{}.{}", variant, tld));
                }
            }
        }

        // Reverse lookup - replace homophones with original
        for replacement in replacements {
            if domain.to_lowercase().contains(replacement) {
                let variant = domain.to_lowercase().replace(replacement, original);
                if variant != domain.to_lowercase() {
                    variations.push(format!("{}.{}", variant, tld));
                }
            }
        }
    }

    variations
}

fn generate_singular_plural(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Simple pluralization rules
    let domain_lower = domain.to_lowercase();

    // Add 's' for simple plural
    if !domain_lower.ends_with('s') {
        variations.push(format!("{}s.{}", domain, tld));
    }

    // Add 'es' for words ending in s, x, z, sh, ch
    if domain_lower.ends_with('s')
        || domain_lower.ends_with('x')
        || domain_lower.ends_with('z')
        || domain_lower.ends_with("sh")
        || domain_lower.ends_with("ch")
    {
        variations.push(format!("{}es.{}", domain, tld));
    }

    // Change 'y' to 'ies'
    if domain_lower.ends_with('y') && domain.len() > 1 {
        let stem = &domain[..domain.len() - 1];
        variations.push(format!("{}ies.{}", stem, tld));
    }

    // Remove 's' for singular (simple case)
    if domain_lower.ends_with('s') && domain.len() > 1 {
        let singular = &domain[..domain.len() - 1];
        variations.push(format!("{}.{}", singular, tld));
    }

    // Remove 'es' for singular
    if domain_lower.ends_with("es") && domain.len() > 2 {
        let singular = &domain[..domain.len() - 2];
        variations.push(format!("{}.{}", singular, tld));
    }

    // Change 'ies' to 'y'
    if domain_lower.ends_with("ies") && domain.len() > 3 {
        let singular = format!("{}y", &domain[..domain.len() - 3]);
        variations.push(format!("{}.{}", singular, tld));
    }

    variations
}

fn generate_wrong_sld(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Common second-level domains for various countries
    let slds = [
        (
            "uk",
            vec!["co.uk", "org.uk", "net.uk", "ac.uk", "gov.uk", "sch.uk"],
        ),
        (
            "au",
            vec!["com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au"],
        ),
        (
            "nz",
            vec!["co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "school.nz"],
        ),
        (
            "za",
            vec!["co.za", "net.za", "org.za", "edu.za", "gov.za", "ac.za"],
        ),
        (
            "ca",
            vec!["co.ca", "net.ca", "org.ca", "gc.ca", "ab.ca", "bc.ca"],
        ),
        (
            "br",
            vec!["com.br", "net.br", "org.br", "edu.br", "gov.br", "mil.br"],
        ),
        (
            "in",
            vec!["co.in", "net.in", "org.in", "edu.in", "gov.in", "ac.in"],
        ),
        (
            "cn",
            vec!["com.cn", "net.cn", "org.cn", "edu.cn", "gov.cn", "ac.cn"],
        ),
        (
            "jp",
            vec!["co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp"],
        ),
    ];

    // Generate wrong SLD variants
    for &(base_tld, ref sld_list) in &slds {
        if tld == base_tld {
            for sld in sld_list {
                variations.push(format!("{}.{}", domain, sld));
            }
        } else {
            for sld in sld_list {
                if tld == *sld {
                    variations.push(format!("{}.{}", domain, base_tld));
                    for other_sld in sld_list {
                        if *other_sld != *sld {
                            variations.push(format!("{}.{}", domain, other_sld));
                        }
                    }
                }
            }
        }
    }

    variations
}

fn generate_domain_prefix(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Common domain prefixes
    let prefixes = [
        "www", "mail", "secure", "admin", "test", "dev", "api", "cdn", "auth", "login", "support",
        "help", "shop", "store", "my", "portal", "mobile", "app", "service", "cloud", "server",
        "vpn", "security", "monitor", "beta",
    ];

    for prefix in &prefixes {
        variations.push(format!("{}-{}.{}", prefix, domain, tld));
        variations.push(format!("{}.{}.{}", prefix, domain, tld));
        variations.push(format!("{}{}.{}", prefix, domain, tld));
    }

    variations
}

fn generate_domain_suffix(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Common domain suffixes
    let suffixes = [
        "app", "site", "web", "online", "pro", "plus", "premium", "club", "group", "tech",
        "service", "platform", "security", "media", "shop", "store", "finance", "health", "gaming",
        "demo", "beta",
    ];

    for suffix in &suffixes {
        variations.push(format!("{}-{}.{}", domain, suffix, tld));
        variations.push(format!("{}{}.{}", domain, suffix, tld));
    }

    variations
}

// ==================== SIMILARITY METRICS ====================

#[derive(Debug, Clone)]
struct SimilarityScore {
    domain: String,
    visual_score: f64,
    cognitive_score: f64,
    combined_score: f64,
}

/// Calculate Levenshtein distance between two strings
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let len1 = s1.chars().count();
    let len2 = s2.chars().count();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut matrix = vec![vec![0usize; len2 + 1]; len1 + 1];

    // Initialize first row and column
    for (i, row) in matrix.iter_mut().enumerate().take(len1 + 1) {
        row[0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    let chars1: Vec<char> = s1.chars().collect();
    let chars2: Vec<char> = s2.chars().collect();

    for (i, &c1) in chars1.iter().enumerate() {
        for (j, &c2) in chars2.iter().enumerate() {
            let cost = if c1 == c2 { 0 } else { 1 };
            matrix[i + 1][j + 1] = std::cmp::min(
                std::cmp::min(
                    matrix[i][j + 1] + 1, // deletion
                    matrix[i + 1][j] + 1, // insertion
                ),
                matrix[i][j] + cost, // substitution
            );
        }
    }

    matrix[len1][len2]
}

/// Calculate homoglyph-weighted visual similarity
fn visual_similarity(original: &str, variant: &str) -> f64 {
    let basic_distance = levenshtein_distance(original, variant) as f64;
    let max_len = std::cmp::max(original.len(), variant.len()) as f64;

    if max_len == 0.0 {
        return 1.0;
    }

    // Base similarity from Levenshtein distance
    let mut similarity = 1.0 - (basic_distance / max_len);

    // Bonus for homoglyph substitutions (characters that look similar)
    let homoglyph_bonus = calculate_homoglyph_similarity(original, variant);

    // Weight the final score
    similarity = (similarity * 0.7) + (homoglyph_bonus * 0.3);

    similarity.clamp(0.0, 1.0)
}

/// Calculate similarity bonus for homoglyph substitutions
fn calculate_homoglyph_similarity(s1: &str, s2: &str) -> f64 {
    if s1.len() != s2.len() {
        return 0.0;
    }

    let chars1: Vec<char> = s1.chars().collect();
    let chars2: Vec<char> = s2.chars().collect();

    let mut homoglyph_matches = 0;
    let mut total_positions = 0;

    // Common homoglyph pairs (visual confusions)
    let homoglyphs = [
        ('a', 'α'),
        ('o', '0'),
        ('i', '1'),
        ('l', '1'),
        ('e', '3'),
        ('s', '$'),
        ('g', '9'),
        ('b', '6'),
        ('z', '2'),
        ('s', '5'),
        ('o', 'ο'),
        ('a', 'а'),
        ('p', 'р'),
        ('c', 'с'),
        ('e', 'е'),
        ('x', 'х'),
        ('y', 'у'),
        ('k', 'κ'),
        ('n', 'η'),
        ('m', 'μ'),
    ];

    for (&c1, &c2) in chars1.iter().zip(chars2.iter()) {
        total_positions += 1;

        if c1 == c2 {
            homoglyph_matches += 1;
        } else {
            // Check if it's a known homoglyph pair
            for &(h1, h2) in &homoglyphs {
                if (c1 == h1 && c2 == h2) || (c1 == h2 && c2 == h1) {
                    homoglyph_matches += 1;
                    break;
                }
            }
        }
    }

    if total_positions == 0 {
        0.0
    } else {
        homoglyph_matches as f64 / total_positions as f64
    }
}

/// Calculate cognitive/phonetic similarity
fn cognitive_similarity(original: &str, variant: &str) -> f64 {
    let mut similarity = 0.0;

    // Phonetic similarity using simple Soundex-like approach
    similarity += phonetic_similarity(original, variant) * 0.4;

    // Semantic similarity based on known cognitive confusions
    similarity += semantic_similarity(original, variant) * 0.3;

    // Length-based similarity penalty
    let length_diff = (original.len() as i32 - variant.len() as i32).abs() as f64;
    let length_penalty = 1.0 - (length_diff / std::cmp::max(original.len(), variant.len()) as f64);
    similarity += length_penalty * 0.3;

    similarity.clamp(0.0, 1.0)
}

/// Simple phonetic similarity calculation
fn phonetic_similarity(s1: &str, s2: &str) -> f64 {
    let sound1 = simple_soundex(s1);
    let sound2 = simple_soundex(s2);

    let distance = levenshtein_distance(&sound1, &sound2) as f64;
    let max_len = std::cmp::max(sound1.len(), sound2.len()) as f64;

    if max_len == 0.0 {
        1.0
    } else {
        1.0 - (distance / max_len)
    }
}

/// Simplified Soundex algorithm for phonetic encoding
fn simple_soundex(s: &str) -> String {
    if s.is_empty() {
        return String::new();
    }

    let mut result = String::new();
    let mut prev_code = None;

    for c in s.to_lowercase().chars() {
        let code = match c {
            'b' | 'f' | 'p' | 'v' => Some('1'),
            'c' | 'g' | 'j' | 'k' | 'q' | 's' | 'x' | 'z' => Some('2'),
            'd' | 't' => Some('3'),
            'l' => Some('4'),
            'm' | 'n' => Some('5'),
            'r' => Some('6'),
            _ => None,
        };

        if let Some(code) = code {
            if prev_code != Some(code) {
                result.push(code);
                prev_code = Some(code);
            }
        } else {
            prev_code = None;
        }
    }

    result
}

/// Calculate semantic similarity based on known word confusions
fn semantic_similarity(original: &str, variant: &str) -> f64 {
    // Check against known cognitive confusion patterns from generate_cognitive
    let cognitive_pairs = [
        ("amazon", "amazom"),
        ("google", "gogle"),
        ("microsoft", "mircosoft"),
        ("facebook", "facbook"),
        ("paypal", "payball"),
        ("secure", "secur"),
        ("support", "suport"),
        ("service", "servic"),
        ("account", "acount"),
        ("login", "loginn"),
        ("portal", "portall"),
        ("center", "centre"),
        ("corp", "corporate"),
        ("inc", "incorporated"),
        ("tech", "technology"),
        ("concordium", "consordium"),
        ("consortium", "concordium"),
    ];

    // Check if this is a known semantic confusion
    for (word1, word2) in &cognitive_pairs {
        if (original.contains(word1) && variant.contains(word2))
            || (original.contains(word2) && variant.contains(word1))
        {
            return 0.8; // High semantic similarity
        }
    }

    // Fallback to basic string similarity
    let distance = levenshtein_distance(original, variant) as f64;
    let max_len = std::cmp::max(original.len(), variant.len()) as f64;

    if max_len == 0.0 {
        1.0
    } else {
        1.0 - (distance / max_len)
    }
}

/// Calculate comprehensive similarity score
fn calculate_similarity(
    original: &str,
    variant: &str,
    _transformation_type: &str,
) -> SimilarityScore {
    let original_domain = original.split('.').next().unwrap_or(original);
    let variant_domain = variant.split('.').next().unwrap_or(variant);

    let visual_score = visual_similarity(original_domain, variant_domain);
    let cognitive_score = cognitive_similarity(original_domain, variant_domain);

    // Weight scores based on transformation type
    let combined_score = match _transformation_type {
        "mixed-encodings" | "idn_homograph" | "mixed_script" => {
            visual_score * 0.8 + cognitive_score * 0.2
        }
        "cognitive" | "homophones" => cognitive_score * 0.8 + visual_score * 0.2,
        "typosquatting" | "omission" | "insertion" => visual_score * 0.6 + cognitive_score * 0.4,
        _ => visual_score * 0.5 + cognitive_score * 0.5,
    };

    SimilarityScore {
        domain: variant.to_string(),
        visual_score,
        cognitive_score,
        combined_score,
    }
}
