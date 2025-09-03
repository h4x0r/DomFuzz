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
struct Cli {
    /// Domain to generate variations for
    domain: String,
    
    /// Enable character substitution variations
    #[arg(long)]
    char_sub: bool,
    
    /// Enable basic Unicode homoglyph variations
    #[arg(long)]
    homoglyphs: bool,
    
    /// Enable misspelling variations (insertion, deletion, transposition)
    #[arg(long)]
    misspellings: bool,
    
    /// Enable TLD variations
    #[arg(long)]
    tld_variations: bool,
    
    /// Enable word part swapping variations
    #[arg(long)]
    word_swap: bool,
    
    /// Enable bitsquatting variations
    #[arg(long)]
    bitsquatting: bool,
    
    /// Enable keyboard proximity variations
    #[arg(long)]
    keyboard: bool,
    
    /// Enable repetition variations
    #[arg(long)]
    repetition: bool,
    
    /// Enable addition variations
    #[arg(long)]
    addition: bool,
    
    /// Enable subdomain injection variations
    #[arg(long)]
    subdomain: bool,
    
    /// Enable combosquatting with common keywords
    #[arg(long)]
    combosquatting: bool,
    
    /// Enable vowel swapping variations
    #[arg(long)]
    vowel_swap: bool,
    
    /// Enable hyphenation variations
    #[arg(long)]
    hyphenation: bool,
    
    /// Enable character omission variations
    #[arg(long)]
    omission: bool,
    
    /// Enable advanced IDN homograph attacks (Unicode/Punycode)
    #[arg(long)]
    idn_homograph: bool,
    
    /// Enable mixed script attacks (Cyrillic + Latin combinations)
    #[arg(long)]
    mixed_script: bool,
    
    /// Enable extended Unicode homoglyphs (160k+ characters)
    #[arg(long)]
    extended_unicode: bool,
    
    /// Enable brand confusion techniques (prefixes/suffixes)
    #[arg(long)]
    brand_confusion: bool,
    
    /// Enable internationalized TLD variations
    #[arg(long)]
    intl_tld: bool,
    
    /// Enable cognitive/semantic word confusion attacks
    #[arg(long)]
    cognitive: bool,
    
    /// Path to dictionary file for combosquatting
    #[arg(long)]
    dictionary: Option<String>,
    
    /// Enable all variation types
    #[arg(long)]
    all: bool,
    
    /// Maximum number of variations to output (unlimited if not specified)
    #[arg(long)]
    max_variations: Option<usize>,
    
    /// Check domain status (available/registered/parked)
    #[arg(long)]
    check_status: bool,
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
        && !cli.intl_tld && !cli.cognitive);
    
    if cli.char_sub || enable_all {
        variations.extend(generate_char_substitutions(&domain_name, &tld));
    }
    
    if cli.homoglyphs || enable_all {
        variations.extend(generate_homoglyphs(&domain_name, &tld));
    }
    
    if cli.misspellings || enable_all {
        variations.extend(generate_misspellings(&domain_name, &tld));
    }
    
    if cli.tld_variations || enable_all {
        variations.extend(generate_tld_variations(&domain_name, &tld));
    }
    
    if cli.word_swap || enable_all {
        variations.extend(generate_word_swaps(&domain_name, &tld));
    }
    
    if cli.bitsquatting || enable_all {
        variations.extend(generate_bitsquatting(&domain_name, &tld));
    }
    
    if cli.keyboard || enable_all {
        variations.extend(generate_keyboard_variations(&domain_name, &tld));
    }
    
    if cli.repetition || enable_all {
        variations.extend(generate_repetition(&domain_name, &tld));
    }
    
    if cli.addition || enable_all {
        variations.extend(generate_addition(&domain_name, &tld));
    }
    
    if cli.subdomain || enable_all {
        variations.extend(generate_subdomain_injection(&domain_name, &tld));
    }
    
    if cli.combosquatting || enable_all {
        let dict_words = if let Some(dict_file) = &cli.dictionary {
            load_dictionary(dict_file)
        } else {
            default_dictionary()
        };
        variations.extend(generate_combosquatting(&domain_name, &tld, &dict_words));
    }
    
    if cli.vowel_swap || enable_all {
        variations.extend(generate_vowel_swapping(&domain_name, &tld));
    }
    
    if cli.hyphenation || enable_all {
        variations.extend(generate_hyphenation(&domain_name, &tld));
    }
    
    if cli.omission || enable_all {
        variations.extend(generate_omission(&domain_name, &tld));
    }
    
    if cli.idn_homograph || enable_all {
        variations.extend(generate_idn_homograph(&domain_name, &tld));
    }
    
    if cli.mixed_script || enable_all {
        variations.extend(generate_mixed_script(&domain_name, &tld));
    }
    
    if cli.extended_unicode || enable_all {
        variations.extend(generate_extended_unicode(&domain_name, &tld));
    }
    
    if cli.brand_confusion || enable_all {
        variations.extend(generate_brand_confusion(&domain_name, &tld));
    }
    
    if cli.intl_tld || enable_all {
        variations.extend(generate_intl_tld(&domain_name, &tld));
    }
    
    if cli.cognitive || enable_all {
        variations.extend(generate_cognitive(&domain_name, &tld));
    }
    
    // Output results
    let mut sorted_variations: Vec<_> = variations.into_iter().collect();
    sorted_variations.sort();
    
    let output_count = if let Some(max) = cli.max_variations {
        max.min(sorted_variations.len())
    } else {
        sorted_variations.len()
    };
    
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
    
    eprintln!("Generated {} variations", sorted_variations.len());
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

fn parse_domain(input: &str) -> (String, String) {
    if let Some(dot_pos) = input.rfind('.') {
        let domain = input[..dot_pos].to_string();
        let tld = input[dot_pos + 1..].to_string();
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
    for i in 0..=domain.len() {
        for ch in "abcdefghijklmnopqrstuvwxyz0123456789".chars() {
            let mut new_domain = domain.to_string();
            new_domain.insert(i, ch);
            variations.push(format!("{}.{}", new_domain, tld));
        }
    }
    
    // Character deletion (omission)
    for i in 0..domain.len() {
        let mut new_domain = domain.to_string();
        new_domain.remove(i);
        if !new_domain.is_empty() {
            variations.push(format!("{}.{}", new_domain, tld));
        }
    }
    
    // Character transposition (adjacent character swapping)
    for i in 0..domain.len().saturating_sub(1) {
        let mut chars: Vec<char> = domain.chars().collect();
        chars.swap(i, i + 1);
        let new_domain: String = chars.into_iter().collect();
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
    
    if domain.len() >= 4 {
        let mid = domain.len() / 2;
        let first_half = &domain[..mid];
        let second_half = &domain[mid..];
        variations.push(format!("{}{}.{}", second_half, first_half, tld));
    }
    
    if domain.len() >= 6 {
        let third = domain.len() / 3;
        let first_third = &domain[..third];
        let middle_third = &domain[third..2*third];
        let last_third = &domain[2*third..];
        variations.push(format!("{}{}{}.{}", last_third, middle_third, first_third, tld));
    }
    
    variations
}

fn generate_bitsquatting(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    for (i, ch) in domain.chars().enumerate() {
        let ch_code = ch as u8;
        for bit_pos in 0..8 {
            let flipped_code = ch_code ^ (1 << bit_pos);
            if let Some(flipped_char) = char::from_u32(flipped_code as u32) {
                if flipped_char.is_ascii_alphabetic() || flipped_char.is_ascii_digit() {
                    let mut new_domain = domain.to_string();
                    new_domain.replace_range(i..i+1, &flipped_char.to_string());
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
    
    for (i, ch) in domain.chars().enumerate() {
        let mut new_domain = domain.to_string();
        new_domain.insert(i + 1, ch);
        variations.push(format!("{}.{}", new_domain, tld));
    }
    
    variations
}

fn generate_addition(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    for ch in "abcdefghijklmnopqrstuvwxyz0123456789".chars() {
        variations.push(format!("{}{}.{}", domain, ch, tld));
        variations.push(format!("{}{}.{}", ch, domain, tld));
    }
    
    for num in 1..=100 {
        variations.push(format!("{}{}.{}", domain, num, tld));
    }
    
    variations
}

fn generate_subdomain_injection(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    for i in 1..domain.len() {
        let mut new_domain = domain.to_string();
        new_domain.insert(i, '.');
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
    
    for i in 1..domain.len() {
        let mut new_domain = domain.to_string();
        new_domain.insert(i, '-');
        variations.push(format!("{}.{}", new_domain, tld));
    }
    
    variations
}

fn generate_omission(domain: &str, tld: &str) -> Vec<String> {
    let mut variations = Vec::new();
    
    for i in 0..domain.len() {
        let mut new_domain = domain.to_string();
        new_domain.remove(i);
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