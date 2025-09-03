use clap::Parser;
use std::collections::HashSet;
use std::time::Duration;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;
use tokio::time::timeout;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Parser)]
#[command(name = "domfuzz")]
#[command(about = "A Rust CLI tool for generating domain name variations using typosquatting techniques")]
#[command(long_about = "DomFuzz generates domain name variations using comprehensive typosquatting techniques.

Algorithms are organized into logical groups for easier usage:

• Basic Typos: Common typing mistakes
• Character Manipulation: Advanced character-level attacks
• Unicode/Script: International character confusion
• Phonetic/Semantic: Sound and meaning based attacks
• Number/Word: Numeric and word form substitution
• Structure: Domain structure manipulation
• Extensions: TLD and branding attacks")]
struct Cli {
    /// Domain to generate variations for
    domain: String,
    
    /// Enable ALL algorithms (default if no specific algorithms selected)
    #[arg(long)]
    all: bool,
    
    /// Limit maximum number of variations to output
    #[arg(long)]
    max_variations: Option<usize>,
    
    /// Check domain availability status (requires network)
    #[arg(long)]
    check_status: bool,
    
    /// Path to dictionary file for combosquatting
    #[arg(long)]
    dictionary: Option<String>,
    
    /// Generate combo attacks by randomly applying multiple algorithms
    #[arg(long)]
    combo: bool,

    // ==================== BASIC TYPOS ====================
    
    /// Enable character substitution variations (common typos like o->0, l->1)
    #[arg(long, help_heading = "Basic Typos")]
    char_sub: bool,
    
    /// Enable misspelling variations (insertion, deletion, transposition)
    #[arg(long, help_heading = "Basic Typos")]
    misspellings: bool,
    
    /// Enable character omission variations
    #[arg(long, help_heading = "Basic Typos")]
    omission: bool,
    
    /// Enable repetition variations (double characters)
    #[arg(long, help_heading = "Basic Typos")]
    repetition: bool,
    
    /// Enable keyboard proximity variations (adjacent key typos)
    #[arg(long, help_heading = "Basic Typos")]
    keyboard: bool,

    // ==================== CHARACTER MANIPULATION ====================
    
    /// Enable bitsquatting variations (bit-flip attacks)
    #[arg(long, help_heading = "Character Manipulation")]
    bitsquatting: bool,
    
    /// Enable double character replacement variations
    #[arg(long, help_heading = "Character Manipulation")]
    double_char_replacement: bool,
    
    /// Enable bidirectional character insertion variations
    #[arg(long, help_heading = "Character Manipulation")]
    bidirectional_insertion: bool,

    // ==================== UNICODE/SCRIPT ATTACKS ====================
    
    /// Enable basic Unicode homoglyph variations
    #[arg(long, help_heading = "Unicode/Script Attacks")]
    homoglyphs: bool,
    
    
    /// Enable advanced IDN homograph attacks (Unicode/Punycode)
    #[arg(long, help_heading = "Unicode/Script Attacks")]
    idn_homograph: bool,
    
    /// Enable mixed script attacks (Cyrillic + Latin combinations)
    #[arg(long, help_heading = "Unicode/Script Attacks")]
    mixed_script: bool,
    
    /// Enable extended Unicode homoglyphs (160k+ characters)
    #[arg(long, help_heading = "Unicode/Script Attacks")]
    extended_unicode: bool,
    
    /// Enable comprehensive Cyrillic substitution variations
    #[arg(long, help_heading = "Unicode/Script Attacks")]
    cyrillic_comprehensive: bool,

    // ==================== PHONETIC/SEMANTIC ====================
    
    /// Enable homophone variations (sound-alike words)
    #[arg(long, help_heading = "Phonetic/Semantic")]
    homophones: bool,
    
    /// Enable vowel swapping variations
    #[arg(long, help_heading = "Phonetic/Semantic")]
    vowel_swap: bool,
    
    /// Enable cognitive/semantic word confusion attacks
    #[arg(long, help_heading = "Phonetic/Semantic")]
    cognitive: bool,
    
    /// Enable singular/plural variations
    #[arg(long, help_heading = "Phonetic/Semantic")]
    singular_plural: bool,

    // ==================== NUMBER/WORD SUBSTITUTION ====================
    
    /// Enable cardinal number substitution variations (one->1)
    #[arg(long, help_heading = "Number/Word Substitution")]
    cardinal_substitution: bool,
    
    /// Enable ordinal number substitution variations (first->1st)
    #[arg(long, help_heading = "Number/Word Substitution")]
    ordinal_substitution: bool,

    // ==================== STRUCTURE MANIPULATION ====================
    
    /// Enable word part swapping variations
    #[arg(long, help_heading = "Structure Manipulation")]
    word_swap: bool,
    
    /// Enable hyphenation variations
    #[arg(long, help_heading = "Structure Manipulation")]
    hyphenation: bool,
    
    /// Enable addition variations (prefix/suffix single chars)
    #[arg(long, help_heading = "Structure Manipulation")]
    addition: bool,
    
    /// Enable subdomain injection variations
    #[arg(long, help_heading = "Structure Manipulation")]
    subdomain: bool,
    
    /// Enable dot insertion variations
    #[arg(long, help_heading = "Structure Manipulation")]
    dot_insertion: bool,
    
    /// Enable dot omission variations
    #[arg(long, help_heading = "Structure Manipulation")]
    dot_omission: bool,
    
    /// Enable dot/hyphen substitution variations
    #[arg(long, help_heading = "Structure Manipulation")]
    dot_hyphen_sub: bool,

    // ==================== DOMAIN EXTENSIONS ====================
    
    /// Enable TLD variations
    #[arg(long, help_heading = "Domain Extensions")]
    tld_variations: bool,
    
    /// Enable internationalized TLD variations
    #[arg(long, help_heading = "Domain Extensions")]
    intl_tld: bool,
    
    /// Enable wrong second-level domain variations
    #[arg(long, help_heading = "Domain Extensions")]
    wrong_sld: bool,
    
    /// Enable combosquatting with common keywords
    #[arg(long, help_heading = "Domain Extensions")]
    combosquatting: bool,
    
    /// Enable brand confusion techniques (authority prefixes/suffixes)
    #[arg(long, help_heading = "Domain Extensions")]
    brand_confusion: bool,
    
    /// Enable domain prefix variations
    #[arg(long, help_heading = "Domain Extensions")]
    domain_prefix: bool,
    
    /// Enable domain suffix variations
    #[arg(long, help_heading = "Domain Extensions")]
    domain_suffix: bool,

}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    
    let (domain_name, tld) = parse_domain(&cli.domain);
    let mut variations = HashSet::new();
    
    let enable_all = cli.all || (!cli.char_sub && !cli.homoglyphs && !cli.misspellings 
        && !cli.tld_variations && !cli.word_swap && !cli.bitsquatting 
        && !cli.keyboard && !cli.repetition && !cli.addition 
        && !cli.subdomain && !cli.combosquatting && !cli.vowel_swap 
        && !cli.hyphenation && !cli.omission && !cli.idn_homograph 
        && !cli.mixed_script && !cli.extended_unicode && !cli.brand_confusion 
        && !cli.intl_tld && !cli.cognitive && !cli.dot_insertion 
        && !cli.dot_omission && !cli.dot_hyphen_sub && !cli.double_char_replacement
        && !cli.bidirectional_insertion && !cli.cardinal_substitution 
        && !cli.ordinal_substitution && !cli.homophones && !cli.singular_plural
        && !cli.wrong_sld && !cli.domain_prefix && !cli.domain_suffix 
        && !cli.cyrillic_comprehensive && !cli.combo);
    
    // Handle combo attacks
    if cli.combo {
        let dict_words = if let Some(dict_file) = &cli.dictionary {
            load_dictionary(dict_file)
        } else {
            default_dictionary()
        };
        
        variations.extend(generate_combo_attacks(&domain_name, &tld, cli.max_variations, &dict_words));
    }
    
    if cli.char_sub || enable_all {
        variations.extend(filter_valid_domains(generate_char_substitutions(&domain_name, &tld)));
    }
    
    if cli.homoglyphs || enable_all {
        variations.extend(filter_valid_domains(generate_homoglyphs(&domain_name, &tld)));
    }
    
    if cli.misspellings || enable_all {
        variations.extend(filter_valid_domains(generate_misspellings(&domain_name, &tld)));
    }
    
    if cli.tld_variations || enable_all {
        variations.extend(filter_valid_domains(generate_tld_variations(&domain_name, &tld)));
    }
    
    if cli.word_swap || enable_all {
        variations.extend(filter_valid_domains(generate_word_swaps(&domain_name, &tld)));
    }
    
    if cli.bitsquatting || enable_all {
        variations.extend(filter_valid_domains(generate_bitsquatting(&domain_name, &tld)));
    }
    
    if cli.keyboard || enable_all {
        variations.extend(filter_valid_domains(generate_keyboard_variations(&domain_name, &tld)));
    }
    
    if cli.repetition || enable_all {
        variations.extend(filter_valid_domains(generate_repetition(&domain_name, &tld)));
    }
    
    if cli.addition || enable_all {
        variations.extend(filter_valid_domains(generate_addition(&domain_name, &tld)));
    }
    
    if cli.subdomain || enable_all {
        variations.extend(filter_valid_domains(generate_subdomain_injection(&domain_name, &tld)));
    }
    
    if cli.combosquatting || enable_all {
        let dict_words = if let Some(dict_file) = &cli.dictionary {
            load_dictionary(dict_file)
        } else {
            default_dictionary()
        };
        variations.extend(filter_valid_domains(generate_combosquatting(&domain_name, &tld, &dict_words)));
    }
    
    if cli.vowel_swap || enable_all {
        variations.extend(filter_valid_domains(generate_vowel_swapping(&domain_name, &tld)));
    }
    
    if cli.hyphenation || enable_all {
        variations.extend(filter_valid_domains(generate_hyphenation(&domain_name, &tld)));
    }
    
    if cli.omission || enable_all {
        variations.extend(filter_valid_domains(generate_omission(&domain_name, &tld)));
    }
    
    if cli.idn_homograph || enable_all {
        variations.extend(filter_valid_domains(generate_idn_homograph(&domain_name, &tld)));
    }
    
    if cli.mixed_script || enable_all {
        variations.extend(filter_valid_domains(generate_mixed_script(&domain_name, &tld)));
    }
    
    if cli.extended_unicode || enable_all {
        variations.extend(filter_valid_domains(generate_extended_unicode(&domain_name, &tld)));
    }
    
    if cli.brand_confusion || enable_all {
        variations.extend(filter_valid_domains(generate_brand_confusion(&domain_name, &tld)));
    }
    
    if cli.intl_tld || enable_all {
        variations.extend(filter_valid_domains(generate_intl_tld(&domain_name, &tld)));
    }
    
    if cli.cognitive || enable_all {
        variations.extend(filter_valid_domains(generate_cognitive(&domain_name, &tld)));
    }
    
    if cli.dot_insertion || enable_all {
        variations.extend(filter_valid_domains(generate_dot_insertion(&domain_name, &tld)));
    }
    
    if cli.dot_omission || enable_all {
        variations.extend(filter_valid_domains(generate_dot_omission(&domain_name, &tld)));
    }
    
    if cli.dot_hyphen_sub || enable_all {
        variations.extend(filter_valid_domains(generate_dot_hyphen_substitution(&domain_name, &tld)));
    }
    
    if cli.double_char_replacement || enable_all {
        variations.extend(filter_valid_domains(generate_double_character_replacement(&domain_name, &tld)));
    }
    
    if cli.bidirectional_insertion || enable_all {
        variations.extend(filter_valid_domains(generate_bidirectional_insertion(&domain_name, &tld)));
    }
    
    if cli.cardinal_substitution || enable_all {
        variations.extend(filter_valid_domains(generate_cardinal_substitution(&domain_name, &tld)));
    }
    
    if cli.ordinal_substitution || enable_all {
        variations.extend(filter_valid_domains(generate_ordinal_substitution(&domain_name, &tld)));
    }
    
    if cli.homophones || enable_all {
        variations.extend(filter_valid_domains(generate_homophones(&domain_name, &tld)));
    }
    
    if cli.singular_plural || enable_all {
        variations.extend(filter_valid_domains(generate_singular_plural(&domain_name, &tld)));
    }
    
    if cli.wrong_sld || enable_all {
        variations.extend(filter_valid_domains(generate_wrong_sld(&domain_name, &tld)));
    }
    
    if cli.domain_prefix || enable_all {
        variations.extend(filter_valid_domains(generate_domain_prefix(&domain_name, &tld)));
    }
    
    if cli.domain_suffix || enable_all {
        variations.extend(filter_valid_domains(generate_domain_suffix(&domain_name, &tld)));
    }
    
    if cli.cyrillic_comprehensive || enable_all {
        variations.extend(filter_valid_domains(generate_cyrillic_comprehensive(&domain_name, &tld)));
    }
    
    // Apply exact max_variations limit - generate more if needed to replace invalid ones
    let mut all_variations: Vec<_> = variations.into_iter().collect();
    all_variations.sort();
    
    let output_count = if let Some(max) = cli.max_variations {
        if all_variations.len() < max && !cli.combo {
            // We need more variations to reach the exact count requested
            // Use combo-style generation to create additional unique variations
            let target_additional = max - all_variations.len();
            let mut additional_variations = HashSet::new();
            let mut attempts = 0;
            let max_attempts = target_additional * 20;
            
            // Generate combinations of existing algorithms to create new variations
            use rand::seq::SliceRandom;
            use rand::thread_rng;
            use rand::Rng;
            let mut rng = thread_rng();
            
            // Define available generators
            let generators: Vec<(&str, Box<dyn Fn(&str, &str) -> Vec<String>>)> = vec![
                ("char_sub", Box::new(|d, t| generate_char_substitutions(d, t))),
                ("homoglyphs", Box::new(|d, t| generate_homoglyphs(d, t))),
                ("misspellings", Box::new(|d, t| generate_misspellings(d, t))),
                ("tld_variations", Box::new(|d, t| generate_tld_variations(d, t))),
                ("keyboard", Box::new(|d, t| generate_keyboard_variations(d, t))),
                ("repetition", Box::new(|d, t| generate_repetition(d, t))),
                ("addition", Box::new(|d, t| generate_addition(d, t))),
                ("omission", Box::new(|d, t| generate_omission(d, t))),
                ("hyphenation", Box::new(|d, t| generate_hyphenation(d, t))),
            ];
            
            while additional_variations.len() < target_additional && attempts < max_attempts {
                attempts += 1;
                
                // Generate a new variation by applying 2-3 random algorithms in sequence
                let mut current_domain = domain_name.clone();
                let mut current_tld = tld.clone();
                let num_transforms = rng.gen_range(2..=3);
                
                for _ in 0..num_transforms {
                    if let Some((_, generator)) = generators.choose(&mut rng) {
                        let results = filter_valid_domains(generator(&current_domain, &current_tld));
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
                    && !additional_variations.contains(&final_domain) {
                    additional_variations.insert(final_domain);
                }
            }
            
            // Add the additional variations
            all_variations.extend(additional_variations);
            all_variations.sort();
        }
        
        // Return exactly the requested number
        max.min(all_variations.len())
    } else {
        all_variations.len()
    };
    
    let sorted_variations = all_variations;
    
    if cli.check_status {
        for variation in sorted_variations.iter().take(output_count) {
            let status = check_domain_status(variation).await;
            println!("{}, {}", variation, status);
        }
    } else {
        for variation in sorted_variations.iter().take(output_count) {
            println!("{}", variation);
        }
    }
    
    eprintln!("Generated {} variations", output_count);
}

async fn check_domain_status(domain: &str) -> String {
    // First check WHOIS for the most accurate information
    if let Ok(whois_result) = check_whois(domain).await {
        return whois_result;
    }
    
    // Fallback to DNS + HTTP checking
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let dns_result = timeout(Duration::from_secs(5), resolver.lookup_ip(domain)).await;
    
    match dns_result {
        Ok(Ok(lookup)) => {
            if lookup.iter().count() == 0 {
                return "available".to_string();
            }
            
            // Domain has DNS records, check if it's parked or active
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
                .build()
                .unwrap_or_default();
            
            // Try HTTP first, then HTTPS
            for protocol in ["http", "https"] {
                let url = format!("{}://{}", protocol, domain);
                if let Ok(response) = timeout(Duration::from_secs(10), client.get(&url).send()).await {
                    if let Ok(resp) = response {
                        if resp.status().is_success() {
                            if let Ok(text) = timeout(Duration::from_secs(5), resp.text()).await {
                                if let Ok(content) = text {
                                    let content_lower = content.to_lowercase();
                                    if content_lower.contains("parked") || 
                                       content_lower.contains("domain for sale") ||
                                       content_lower.contains("this domain may be for sale") ||
                                       content_lower.contains("godaddy") && content_lower.contains("parked") ||
                                       content_lower.contains("sedo") ||
                                       content_lower.contains("parking") ||
                                       content_lower.contains("under construction") ||
                                       content_lower.contains("coming soon") {
                                        return "parked".to_string();
                                    }
                                }
                            }
                            return "registered".to_string();
                        }
                    }
                }
            }
            
            "registered".to_string()
        }
        Ok(Err(_)) => "available".to_string(),
        Err(_) => "timeout".to_string(),
    }
}

async fn check_whois(domain: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let tld = domain.split('.').last().unwrap_or("");
    let whois_server = get_whois_server(tld);
    
    // Connect to WHOIS server
    let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(&whois_server)).await??;
    
    // Send WHOIS query
    let query = format!("{}\r\n", domain);
    timeout(Duration::from_secs(5), stream.write_all(query.as_bytes())).await??;
    
    // Read response
    let mut response = Vec::new();
    timeout(Duration::from_secs(10), stream.read_to_end(&mut response)).await??;
    let whois_data = String::from_utf8_lossy(&response).to_lowercase();
    
    // Analyze WHOIS response
    if whois_data.contains("no match") ||
       whois_data.contains("not found") ||
       whois_data.contains("no entries found") ||
       whois_data.contains("domain status: available") ||
       whois_data.contains("domain not found") ||
       whois_data.contains("no data found") {
        Ok("available".to_string())
    } else if whois_data.contains("registrar:") ||
              whois_data.contains("registrant:") ||
              whois_data.contains("creation date:") ||
              whois_data.contains("created:") {
        // Check if it's parked based on WHOIS data
        if whois_data.contains("parked") ||
           whois_data.contains("parking") ||
           whois_data.contains("domain for sale") ||
           whois_data.contains("sedo") ||
           whois_data.contains("bodis") ||
           whois_data.contains("sedoparking") {
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
                // Allow non-ASCII for Unicode/IDN attacks, but reject other invalid chars
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
        .collect()
}

fn generate_combo_attacks(domain: &str, tld: &str, max_variations: Option<usize>, _dict_words: &[String]) -> Vec<String> {
    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use rand::Rng;
    
    let mut variations = Vec::new();
    let mut rng = thread_rng();
    
    // Define all available attack functions
    let attack_functions: Vec<(&str, Box<dyn Fn(&str, &str) -> Vec<String>>)> = vec![
        ("char_sub", Box::new(|d, t| generate_char_substitutions(d, t))),
        ("homoglyphs", Box::new(|d, t| generate_homoglyphs(d, t))),
        ("misspellings", Box::new(|d, t| generate_misspellings(d, t))),
        ("keyboard", Box::new(|d, t| generate_keyboard_variations(d, t))),
        ("repetition", Box::new(|d, t| generate_repetition(d, t))),
        ("addition", Box::new(|d, t| generate_addition(d, t))),
        ("vowel_swap", Box::new(|d, t| generate_vowel_swapping(d, t))),
        ("hyphenation", Box::new(|d, t| generate_hyphenation(d, t))),
        ("omission", Box::new(|d, t| generate_omission(d, t))),
        ("word_swap", Box::new(|d, t| generate_word_swaps(d, t))),
        ("bitsquatting", Box::new(|d, t| generate_bitsquatting(d, t))),
        ("dot_insertion", Box::new(|d, t| generate_dot_insertion(d, t))),
        ("dot_omission", Box::new(|d, t| generate_dot_omission(d, t))),
        ("double_char_replacement", Box::new(|d, t| generate_double_character_replacement(d, t))),
        ("bidirectional_insertion", Box::new(|d, t| generate_bidirectional_insertion(d, t))),
        ("cardinal_substitution", Box::new(|d, t| generate_cardinal_substitution(d, t))),
        ("ordinal_substitution", Box::new(|d, t| generate_ordinal_substitution(d, t))),
        ("homophones", Box::new(|d, t| generate_homophones(d, t))),
        ("singular_plural", Box::new(|d, t| generate_singular_plural(d, t))),
        ("cyrillic_comprehensive", Box::new(|d, t| generate_cyrillic_comprehensive(d, t))),
    ];
    
    // Generate combo variations by applying random sequences of attacks
    let target_variations = max_variations.unwrap_or(100); // Default to 100 if no limit specified
    let mut attempts = 0;
    let max_attempts = target_variations * 10; // Prevent infinite loops
    
    while variations.len() < target_variations && attempts < max_attempts {
        attempts += 1;
        let mut current_domain = domain.to_string();
        let mut current_tld = tld.to_string();
        let mut applied_attacks = Vec::new();
        
        // Randomly choose number of attacks (2-5)
        let num_attacks = rng.gen_range(2..=5);
        
        // Apply random attacks (allowing repeats)
        for _ in 0..num_attacks {
            if let Some((attack_name, attack_fn)) = attack_functions.choose(&mut rng) {
                // Apply the attack and randomly select one result
                let attack_results = attack_fn(&current_domain, &current_tld);
                if !attack_results.is_empty() {
                    if let Some(selected_result) = attack_results.choose(&mut rng) {
                        // Parse the result to separate domain and TLD for next iteration
                        let (parsed_domain, parsed_tld) = parse_domain(selected_result);
                        current_domain = parsed_domain;
                        current_tld = parsed_tld;
                        applied_attacks.push(*attack_name);
                    }
                }
            }
        }
        
        // Only add if we successfully applied at least 2 attacks
        if applied_attacks.len() >= 2 {
            let final_domain = format!("{}.{}", current_domain, current_tld);
            if final_domain != format!("{}.{}", domain, tld) 
                && !variations.contains(&final_domain) 
                && is_valid_domain(&final_domain) {
                variations.push(final_domain);
            }
        }
    }
    
    variations
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

fn generate_char_substitutions(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    let substitutions = [
        ('o', '0'), ('l', '1'), ('i', '1'), ('e', '3'), ('a', '@'),
        ('s', '$'), ('g', '9'), ('b', '6'), ('t', '7'), ('z', '2'),
    ];
    
    for &(from, to) in &substitutions {
        let substituted = domain.replace(from, &to.to_string());
        if substituted != domain {
            variations.push(format!("{}.{}", substituted, tld));
        }
    }
    
    variations
}

fn generate_cognitive(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    // Cognitive/semantic word confusion attacks
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
        
        // Common domain confusions (sophisticated attacks like concordium->consordium)
        ("concordium", vec!["consordium", "consortium", "concardium"]),
        ("consortium", vec!["consordium", "concordium", "consortum"]),
        ("foundation", vec!["fundation", "foundtion", "foundaton"]),
        ("enterprise", vec!["enterprize", "enterpise", "enterpris"]),
        ("international", vec!["internacional", "internation", "intl"]),
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
        ("communications", vec!["communication", "comm", "comunications"]),
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
    
    // Phonetic similarity attacks (sounds-like transformations)
    let phonetic_substitutions = [
        ("ph", "f"), ("f", "ph"),
        ("ck", "k"), ("k", "ck"),  
        ("c", "k"), ("k", "c"),
        ("s", "z"), ("z", "s"),
        ("i", "y"), ("y", "i"),
        ("er", "or"), ("or", "er"),
        ("an", "en"), ("en", "an"),
        ("tion", "sion"), ("sion", "tion"),
    ];
    
    for &(from, to) in &phonetic_substitutions {
        if domain.contains(from) {
            let phonetic_variant = domain.replace(from, to);
            if phonetic_variant != domain {
                variations.push(format!("{}.{}", phonetic_variant, tld));
            }
        }
    }
    
    // Compound word separation attacks
    let common_compounds = [
        "facebook", "youtube", "linkedin", "instagram", "microsoft",
        "paypal", "amazon", "google", "twitter", "whatsapp",
        "airbnb", "spotify", "netflix", "dropbox", "github"
    ];
    
    for compound in &common_compounds {
        if domain.to_lowercase().contains(compound) {
            // Try to split compound words intelligently
            match *compound {
                "facebook" => {
                    variations.push(format!("{}.{}", domain.to_lowercase().replace("facebook", "face-book"), tld));
                    variations.push(format!("{}.{}", domain.to_lowercase().replace("facebook", "faceb00k"), tld));
                }
                "youtube" => {
                    variations.push(format!("{}.{}", domain.to_lowercase().replace("youtube", "you-tube"), tld));
                    variations.push(format!("{}.{}", domain.to_lowercase().replace("youtube", "youtub3"), tld));
                }
                "linkedin" => {
                    variations.push(format!("{}.{}", domain.to_lowercase().replace("linkedin", "linked-in"), tld));
                    variations.push(format!("{}.{}", domain.to_lowercase().replace("linkedin", "link3din"), tld));
                }
                "instagram" => {
                    variations.push(format!("{}.{}", domain.to_lowercase().replace("instagram", "insta-gram"), tld));
                    variations.push(format!("{}.{}", domain.to_lowercase().replace("instagram", "instagr4m"), tld));
                }
                "microsoft" => {
                    variations.push(format!("{}.{}", domain.to_lowercase().replace("microsoft", "micro-soft"), tld));
                    variations.push(format!("{}.{}", domain.to_lowercase().replace("microsoft", "micr0soft"), tld));
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

fn generate_homoglyphs(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    let homographs = [
        ('a', 'а'), ('e', 'е'), ('o', 'о'), ('p', 'р'), ('c', 'с'), ('y', 'у'), ('x', 'х'),
        ('a', 'α'), ('o', 'ο'), ('p', 'ρ'), ('v', 'ν'), ('u', 'υ'),
    ];
    
    for &(latin, homograph) in &homographs {
        let substituted = domain.replace(latin, &homograph.to_string());
        if substituted != domain {
            variations.push(format!("{}.{}", substituted, tld));
        }
    }
    
    variations
}

fn generate_misspellings(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    // Character insertion - full alphabet
    let char_indices: Vec<_> = domain.char_indices().map(|(i, _)| i).chain(std::iter::once(domain.len())).collect();
    for &byte_pos in &char_indices {
        for ch in "abcdefghijklmnopqrstuvwxyz0123456789".chars() {
            let mut new_domain = domain.to_string();
            new_domain.insert(byte_pos, ch);
            variations.push(format!("{}.{}", new_domain, tld));
        }
    }
    
    // Character deletion (omission) - using char-based approach
    for i in 0..domain.chars().count() {
        let mut chars: Vec<char> = domain.chars().collect();
        chars.remove(i);
        if !chars.is_empty() {
            let new_domain: String = chars.into_iter().collect();
            variations.push(format!("{}.{}", new_domain, tld));
        }
    }
    
    // Character transposition (adjacent character swapping)
    let chars: Vec<char> = domain.chars().collect();
    for i in 0..chars.len().saturating_sub(1) {
        let mut char_copy = chars.clone();
        char_copy.swap(i, i + 1);
        let new_domain: String = char_copy.into_iter().collect();
        variations.push(format!("{}.{}", new_domain, tld));
    }
    
    // Character substitution with common typos
    let substitution_chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (i, _) in domain.chars().enumerate() {
        for ch in substitution_chars.chars() {
            let mut chars: Vec<char> = domain.chars().collect();
            if chars[i] != ch {
                chars[i] = ch;
                let new_domain: String = chars.into_iter().collect();
                variations.push(format!("{}.{}", new_domain, tld));
            }
        }
    }
    
    variations
}

fn generate_tld_variations(domain: &str, _tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    let tlds = [
        "com", "net", "org", "info", "biz", "us", "co", "io", "me",
        "app", "dev", "tech", "online", "site", "store", "shop",
        "uk", "ca", "de", "fr", "ru", "cn", "jp", "au", "br",
        "tk", "ml", "ga", "cf"
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
        let middle_third: String = chars[third..2*third].iter().collect();
        let last_third: String = chars[2*third..].iter().collect();
        variations.push(format!("{}{}{}.{}", last_third, middle_third, first_third, tld));
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
                    new_domain.push_str(&chars[i+1..].iter().collect::<String>());
                    variations.push(format!("{}.{}", new_domain, tld));
                }
            }
        }
    }
    
    variations
}

fn generate_keyboard_variations(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    let qwerty_map = [
        ('q', "wa"), ('w', "qes"), ('e', "wrd"), ('r', "etf"), ('t', "rgy"), ('y', "tuh"), 
        ('u', "yio"), ('i', "uop"), ('o', "ip"), ('p', "o"),
        ('a', "qsz"), ('s', "awdz"), ('d', "sefx"), ('f', "dgrc"), ('g', "fthv"), ('h', "gyjb"), 
        ('j', "hukn"), ('k', "julm"), ('l', "km"), 
        ('z', "asx"), ('x', "zsdc"), ('c', "xdfv"), ('v', "cfgb"), ('b', "vghn"), ('n', "bhjm"), 
        ('m', "njk")
    ];
    
    for (orig_char, adjacent_chars) in &qwerty_map {
        for adj_char in adjacent_chars.chars() {
            let substituted = domain.replace(*orig_char, &adj_char.to_string());
            if substituted != domain {
                variations.push(format!("{}.{}", substituted, tld));
            }
        }
    }
    
    variations
}

fn generate_repetition(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    let chars: Vec<char> = domain.chars().collect();
    
    for (i, &ch) in chars.iter().enumerate() {
        let mut new_domain = String::new();
        new_domain.push_str(&chars[..=i].iter().collect::<String>());
        new_domain.push(ch);
        new_domain.push_str(&chars[i+1..].iter().collect::<String>());
        variations.push(format!("{}.{}", new_domain, tld));
    }
    
    variations
}

fn generate_addition(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    for ch in "abcdefghijklmnopqrstuvwxyz0123456789".chars() {
        // Check length limits (63 chars per label, 253 total)
        let suffix_variant = format!("{}{}", domain, ch);
        let prefix_variant = format!("{}{}", ch, domain);
        
        if suffix_variant.len() <= 63 {
            variations.push(format!("{}.{}", suffix_variant, tld));
        }
        if prefix_variant.len() <= 63 {
            variations.push(format!("{}.{}", prefix_variant, tld));
        }
    }
    
    for num in 1..=100 {
        let suffix_variant = format!("{}{}", domain, num);
        if suffix_variant.len() <= 63 {
            variations.push(format!("{}.{}", suffix_variant, tld));
        }
    }
    
    variations
}

fn generate_subdomain_injection(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    let chars: Vec<char> = domain.chars().collect();
    for i in 1..chars.len() {
        // Skip positions that would create consecutive dots
        if i > 0 && chars[i-1] == '.' {
            continue;
        }
        if i < chars.len() && chars[i] == '.' {
            continue;
        }
        
        // Convert char index to byte index for insertion
        let byte_pos = domain.char_indices().nth(i).map(|(pos, _)| pos).unwrap_or(domain.len());
        let mut new_domain = domain.to_string();
        new_domain.insert(byte_pos, '.');
        variations.push(format!("{}.{}", new_domain, tld));
    }
    
    variations
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
    vec![
        "support", "secure", "login", "pay", "help", "service", "account", "portal", "center", "app",
        "online", "store", "shop", "mail", "cloud", "data", "mobile", "web", "digital", "tech",
        "pro", "plus", "premium", "official", "admin", "manage", "bank", "finance", "crypto",
    ].into_iter().map(|s| s.to_string()).collect()
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

fn generate_vowel_swapping(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    let vowel_swaps = [('a', 'e'), ('e', 'i'), ('i', 'o'), ('o', 'u'), ('u', 'a')];
    
    for &(from, to) in &vowel_swaps {
        let substituted = domain.replace(from, &to.to_string());
        if substituted != domain {
            variations.push(format!("{}.{}", substituted, tld));
        }
    }
    
    variations
}

fn generate_hyphenation(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    let chars: Vec<char> = domain.chars().collect();
    for i in 1..chars.len() {
        // Skip positions that would create domains starting/ending with hyphens
        // or consecutive hyphens
        if i > 0 && chars[i-1] == '-' {
            continue;
        }
        if i < chars.len() && chars[i] == '-' {
            continue;
        }
        
        // Convert char index to byte index for insertion
        let byte_pos = domain.char_indices().nth(i).map(|(pos, _)| pos).unwrap_or(domain.len());
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

fn generate_omission(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    let chars: Vec<char> = domain.chars().collect();
    
    for i in 0..chars.len() {
        let mut new_domain = String::new();
        new_domain.push_str(&chars[..i].iter().collect::<String>());
        new_domain.push_str(&chars[i+1..].iter().collect::<String>());
        
        if !new_domain.is_empty() {
            variations.push(format!("{}.{}", new_domain, tld));
        }
    }
    
    variations
}

fn generate_idn_homograph(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    let idn_mappings = [
        ('a', 'а'), ('e', 'е'), ('o', 'о'), ('p', 'р'), ('c', 'с'), ('y', 'у'), ('x', 'х'),
        ('a', 'α'), ('o', 'ο'), ('p', 'ρ'), ('v', 'ν'), ('u', 'υ'),
        ('i', 'і'), ('j', 'ј'), ('s', 'ѕ'),
    ];
    
    for &(latin, homograph) in &idn_mappings {
        let domain_chars: Vec<char> = domain.chars().collect();
        for (i, &ch) in domain_chars.iter().enumerate() {
            if ch == latin {
                let mut new_domain = domain_chars.clone();
                new_domain[i] = homograph;
                let homograph_domain: String = new_domain.into_iter().collect();
                variations.push(format!("{}.{}", homograph_domain, tld));
            }
        }
    }
    
    variations
}

fn generate_mixed_script(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    let mixed_mappings = [
        ("google", "gооgle"), ("amazon", "аmazon"), ("paypal", "рaypal"), ("apple", "аpple"),
        ("google", "goοgle"), ("amazon", "αmazon"), ("yahoo", "yahoο"),
    ];
    
    for &(original, mixed) in &mixed_mappings {
        if domain.to_lowercase().contains(original) {
            let mixed_domain = domain.to_lowercase().replace(original, mixed);
            if mixed_domain != domain.to_lowercase() {
                variations.push(format!("{}.{}", mixed_domain, tld));
            }
        }
    }
    
    variations
}

fn generate_extended_unicode(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    let extended_mappings = [
        ('a', 'ａ'), ('b', 'ｂ'), ('c', 'ｃ'), ('d', 'ｄ'), ('e', 'ｅ'),
        ('f', 'ｆ'), ('g', 'ｇ'), ('h', 'ｈ'), ('i', 'ｉ'), ('j', 'ｊ'),
        ('i', 'і'), ('j', 'ј'), ('s', 'ѕ'),
    ];
    
    for &(latin, unicode_char) in &extended_mappings {
        let domain_chars: Vec<char> = domain.chars().collect();
        for (i, &ch) in domain_chars.iter().enumerate() {
            if ch == latin {
                let mut new_domain = domain_chars.clone();
                new_domain[i] = unicode_char;
                let unicode_domain: String = new_domain.into_iter().collect();
                variations.push(format!("{}.{}", unicode_domain, tld));
            }
        }
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
        ("com", "ком"), ("net", "нет"), ("org", "орг"),
        ("com", "كوم"), ("net", "شبكة"), ("org", "منظمة"),
        ("com", "公司"), ("net", "网络"), ("org", "组织"), ("cn", "中国"),
        ("com", "コム"), ("net", "ネット"), ("org", "オルグ"),
        ("com", "컴"), ("net", "넷"), ("kr", "한국"),
        ("com", "κομ"), ("net", "δικτυο"), ("org", "οργ"), ("gr", "ελ"),
        ("com", "קום"), ("net", "רשת"), ("org", "ארג"),
        ("com", "คอม"), ("net", "เน็ต"), ("th", "ไทย"),
        ("com", "कॉम"), ("net", "नेट"), ("org", "संगठन"), ("in", "भारत"),
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
        if i > 0 && chars[i-1] == '.' {
            continue;
        }
        if i < chars.len() && chars[i] == '.' {
            continue;
        }
        
        // Convert char index to byte index for insertion
        let byte_pos = domain.char_indices().nth(i).map(|(pos, _)| pos).unwrap_or(domain.len());
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

fn generate_double_character_replacement(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    // Adjacent keyboard mappings for double character replacement
    let qwerty_map = [
        ('q', "wa"), ('w', "qes"), ('e', "wrd"), ('r', "etf"), ('t', "rgy"), ('y', "tuh"), 
        ('u', "yio"), ('i', "uop"), ('o', "ip"), ('p', "o"),
        ('a', "qsz"), ('s', "awdz"), ('d', "sefx"), ('f', "dgrc"), ('g', "fthv"), ('h', "gyjb"), 
        ('j', "hukn"), ('k', "julm"), ('l', "km"), 
        ('z', "asx"), ('x', "zsdc"), ('c', "xdfv"), ('v', "cfgb"), ('b', "vghn"), ('n', "bhjm"), 
        ('m', "njk")
    ];
    
    let chars: Vec<char> = domain.chars().collect();
    
    for (i, &ch) in chars.iter().enumerate() {
        // Find adjacent keys and replace with double characters
        for (orig_char, adjacent_chars) in &qwerty_map {
            if ch == *orig_char {
                for adj_char in adjacent_chars.chars() {
                    let mut new_domain = String::new();
                    new_domain.push_str(&chars[..i].iter().collect::<String>());
                    new_domain.push_str(&format!("{}{}", adj_char, adj_char));
                    new_domain.push_str(&chars[i+1..].iter().collect::<String>());
                    
                    if new_domain != domain {
                        variations.push(format!("{}.{}", new_domain, tld));
                    }
                }
            }
        }
    }
    
    variations
}

fn generate_bidirectional_insertion(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    // Adjacent keyboard mappings for bidirectional insertion
    let qwerty_map = [
        ('q', "wa"), ('w', "qes"), ('e', "wrd"), ('r', "etf"), ('t', "rgy"), ('y', "tuh"), 
        ('u', "yio"), ('i', "uop"), ('o', "ip"), ('p', "o"),
        ('a', "qsz"), ('s', "awdz"), ('d', "sefx"), ('f', "dgrc"), ('g', "fthv"), ('h', "gyjb"), 
        ('j', "hukn"), ('k', "julm"), ('l', "km"), 
        ('z', "asx"), ('x', "zsdc"), ('c', "xdfv"), ('v', "cfgb"), ('b', "vghn"), ('n', "bhjm"), 
        ('m', "njk")
    ];
    
    for (char_idx, ch) in domain.chars().enumerate() {
        // Find adjacent keys for each character
        for (orig_char, adjacent_chars) in &qwerty_map {
            if ch == *orig_char {
                for adj_char in adjacent_chars.chars() {
                    // Get byte positions for insertion
                    let char_positions: Vec<_> = domain.char_indices().collect();
                    let byte_pos_before = char_positions.get(char_idx).map(|(pos, _)| *pos).unwrap_or(domain.len());
                    let byte_pos_after = char_positions.get(char_idx + 1).map(|(pos, _)| *pos).unwrap_or(domain.len());
                    
                    // Insert adjacent character before current character
                    let mut before_domain = domain.to_string();
                    before_domain.insert(byte_pos_before, adj_char);
                    variations.push(format!("{}.{}", before_domain, tld));
                    
                    // Insert adjacent character after current character
                    let mut after_domain = domain.to_string();
                    after_domain.insert(byte_pos_after, adj_char);
                    variations.push(format!("{}.{}", after_domain, tld));
                }
            }
        }
    }
    
    variations
}

fn generate_cardinal_substitution(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    // Cardinal number mappings (digit to word and word to digit)
    let cardinals = [
        ("0", "zero"), ("1", "one"), ("2", "two"), ("3", "three"), ("4", "four"),
        ("5", "five"), ("6", "six"), ("7", "seven"), ("8", "eight"), ("9", "nine"),
        ("10", "ten"), ("11", "eleven"), ("12", "twelve"), ("20", "twenty"),
        ("30", "thirty"), ("40", "forty"), ("50", "fifty"), ("100", "hundred"),
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
        ("1st", "first"), ("2nd", "second"), ("3rd", "third"), ("4th", "fourth"), ("5th", "fifth"),
        ("6th", "sixth"), ("7th", "seventh"), ("8th", "eighth"), ("9th", "ninth"), ("10th", "tenth"),
        ("11th", "eleventh"), ("12th", "twelfth"), ("20th", "twentieth"), ("21st", "twentyfirst"),
        ("30th", "thirtieth"), ("100th", "hundredth"),
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
    if domain_lower.ends_with('s') || domain_lower.ends_with('x') || domain_lower.ends_with('z') 
       || domain_lower.ends_with("sh") || domain_lower.ends_with("ch") {
        variations.push(format!("{}es.{}", domain, tld));
    }
    
    // Change 'y' to 'ies' 
    if domain_lower.ends_with('y') && domain.len() > 1 {
        let stem = &domain[..domain.len()-1];
        variations.push(format!("{}ies.{}", stem, tld));
    }
    
    // Remove 's' for singular (simple case)
    if domain_lower.ends_with('s') && domain.len() > 1 {
        let singular = &domain[..domain.len()-1];
        variations.push(format!("{}.{}", singular, tld));
    }
    
    // Remove 'es' for singular
    if domain_lower.ends_with("es") && domain.len() > 2 {
        let singular = &domain[..domain.len()-2];
        variations.push(format!("{}.{}", singular, tld));
    }
    
    // Change 'ies' to 'y'
    if domain_lower.ends_with("ies") && domain.len() > 3 {
        let singular = format!("{}y", &domain[..domain.len()-3]);
        variations.push(format!("{}.{}", singular, tld));
    }
    
    variations
}

fn generate_wrong_sld(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    // Common second-level domains for various countries
    let slds = [
        ("uk", vec!["co.uk", "org.uk", "net.uk", "ac.uk", "gov.uk", "sch.uk"]),
        ("au", vec!["com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au"]),
        ("nz", vec!["co.nz", "net.nz", "org.nz", "ac.nz", "govt.nz", "school.nz"]),
        ("za", vec!["co.za", "net.za", "org.za", "edu.za", "gov.za", "ac.za"]),
        ("ca", vec!["co.ca", "net.ca", "org.ca", "gc.ca", "ab.ca", "bc.ca"]),
        ("br", vec!["com.br", "net.br", "org.br", "edu.br", "gov.br", "mil.br"]),
        ("in", vec!["co.in", "net.in", "org.in", "edu.in", "gov.in", "ac.in"]),
        ("cn", vec!["com.cn", "net.cn", "org.cn", "edu.cn", "gov.cn", "ac.cn"]),
        ("jp", vec!["co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ad.jp"]),
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
        "www", "mail", "secure", "admin", "test", "dev", "api", "cdn", "auth", "login",
        "support", "help", "shop", "store", "my", "portal", "mobile", "app", "service",
        "cloud", "server", "vpn", "security", "monitor", "beta",
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
        "service", "platform", "security", "media", "shop", "store", "finance", "health",
        "gaming", "demo", "beta",
    ];
    
    for suffix in &suffixes {
        variations.push(format!("{}-{}.{}", domain, suffix, tld));
        variations.push(format!("{}{}.{}", domain, suffix, tld));
    }
    
    variations
}

fn generate_cyrillic_comprehensive(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    // Comprehensive Latin to Cyrillic mappings
    let cyrillic_mappings = [
        ('a', 'а'), ('c', 'с'), ('e', 'е'), ('o', 'о'), ('p', 'р'), ('x', 'х'), ('y', 'у'),
        ('i', 'і'), ('j', 'ј'), ('s', 'ѕ'), ('b', 'б'), ('d', 'д'), ('f', 'ф'), ('g', 'г'), 
        ('h', 'н'), ('k', 'к'), ('l', 'л'), ('m', 'м'), ('n', 'н'), ('r', 'р'), ('t', 'т'), 
        ('v', 'в'), ('z', 'з'), ('w', 'в'), ('q', 'к'),
    ];
    
    // Single character substitutions
    for &(latin, cyrillic) in &cyrillic_mappings {
        let substituted = domain.replace(latin, &cyrillic.to_string());
        if substituted != domain {
            variations.push(format!("{}.{}", substituted, tld));
        }
    }
    
    // Mixed script variations (partial substitution)
    let chars: Vec<char> = domain.chars().collect();
    for (i, &ch) in chars.iter().enumerate() {
        for &(latin, cyrillic) in &cyrillic_mappings {
            if ch == latin {
                let mut mixed_chars = chars.clone();
                mixed_chars[i] = cyrillic;
                let mixed_domain: String = mixed_chars.into_iter().collect();
                if mixed_domain != domain {
                    variations.push(format!("{}.{}", mixed_domain, tld));
                }
            }
        }
    }
    
    variations
}