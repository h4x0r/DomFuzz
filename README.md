# DomFuzz

A comprehensive domain name fuzzing tool written in Rust for generating typosquatting variations used in cybersecurity research and defensive purposes.

## Overview

DomFuzz generates domain name variations using advanced typosquatting techniques commonly employed in phishing campaigns and cybersquatting attacks. The tool implements algorithms from leading domain fuzzing tools like URLCrazy, dnstwist, URLInsane, and DomainFuzz, providing comprehensive coverage of domain manipulation techniques.

## Features

- **30+ fuzzing algorithms** organized into logical groups
- **Network status checking** for domain availability
- **Customizable output** with variation limits
- **Dictionary-based combosquatting** with custom wordlists
- **Unicode and international** character support
- **High performance** Rust implementation

## Installation

### From Source
```bash
git clone https://github.com/yourusername/domfuzz
cd domfuzz
cargo build --release
```

### Usage
```bash
cargo run -- [OPTIONS] <DOMAIN>
```

## Algorithm Groups

DomFuzz organizes its algorithms into logical groups for easier usage:

### 🔤 Basic Typos
Common typing mistakes and simple character errors:
- **Character Substitution**: `o→0`, `l→1`, `e→3`, etc.
- **Misspellings**: Character insertion, deletion, transposition
- **Character Omission**: Missing characters
- **Repetition**: Double characters (`google→gooogle`)  
- **Keyboard Proximity**: Adjacent key typos based on QWERTY layout

```bash
cargo run -- --char-sub --keyboard google.com
```

### 🔧 Character Manipulation
Advanced character-level attack techniques:
- **Bitsquatting**: Single bit-flip attacks
- **Double Character Replacement**: QWERTY-based double char substitution
- **Bidirectional Insertion**: Adjacent character insertion in both directions

```bash
cargo run -- --bitsquatting --double-char-replacement example.com
```

### 🌐 Unicode/Script Attacks
International character confusion attacks:
- **Basic Homoglyphs**: Visually similar characters (`a→α`)
- **IDN Homograph**: Advanced Unicode/Punycode attacks
- **Mixed Script**: Cyrillic + Latin character mixing
- **Extended Unicode**: 160k+ character homoglyph support
- **Cyrillic Comprehensive**: Extensive Cyrillic substitutions

```bash
cargo run -- --homoglyphs --cyrillic-comprehensive paypal.com
```

### 🗣️ Phonetic/Semantic
Sound and meaning-based attacks:
- **Homophones**: Sound-alike word replacements (`right→write`)
- **Vowel Swapping**: Vowel interchange (`a↔e`, `i↔o`)
- **Cognitive**: Semantic word confusion attacks
- **Singular/Plural**: Word form variations (`bank→banks`)

```bash
cargo run -- --homophones --cognitive facebook.com
```

### 🔢 Number/Word Substitution
Numeric and word form manipulation:
- **Cardinal Substitution**: Number-to-word conversion (`one→1`)
- **Ordinal Substitution**: Ordinal conversion (`first→1st`)

```bash
cargo run -- --cardinal-substitution --ordinal-substitution first1.com
```

### 🏗️ Structure Manipulation
Domain structure and format changes:
- **Word Swapping**: Domain part rearrangement
- **Hyphenation**: Hyphen insertion (`facebook→face-book`)
- **Addition**: Prefix/suffix single character addition
- **Subdomain Injection**: Internal dot insertion
- **Dot Insertion/Omission**: Dot manipulation
- **Dot/Hyphen Substitution**: Dot-hyphen interchange

```bash
cargo run -- --hyphenation --dot-insertion google.com
```

### 🌍 Domain Extensions
TLD and branding manipulation:
- **TLD Variations**: Alternative top-level domains
- **International TLD**: IDN TLD variations (`.com→.көм`)
- **Wrong SLD**: Incorrect second-level domains (`.co.uk→.co.gov.uk`)
- **Combosquatting**: Keyword combination attacks
- **Brand Confusion**: Authority prefixes/suffixes (`secure-`, `-official`)
- **Domain Prefix/Suffix**: Common domain extensions

```bash
cargo run -- --tld-variations --brand-confusion --combosquatting amazon.com
```

## Usage Examples

### Basic Usage
```bash
# Generate all variations (default behavior)
cargo run -- example.com

# Use specific algorithm groups
cargo run -- --basic-typos --unicode-attacks example.com

# Limit output and check status
cargo run -- --all --max-variations 50 --check-status example.com
```

### Advanced Usage
```bash
# Custom dictionary for combosquatting
cargo run -- --combosquatting --dictionary /path/to/wordlist.txt target.com

# Focus on international attacks
cargo run -- --cyrillic-comprehensive --idn-homograph --intl-tld example.com

# Phonetic and semantic attacks only
cargo run -- --homophones --cognitive --singular-plural rightmove.com
```

### Real-World Examples

**Banking/Finance Focus:**
```bash
cargo run -- --brand-confusion --cognitive --homoglyphs paypal.com
```

**Social Media Focus:**
```bash
cargo run -- --cognitive --homophones --hyphenation facebook.com
```

**Technology Company Focus:**
```bash
cargo run -- --cyrillic-comprehensive --brand-confusion microsoft.com
```

## Output Format

DomFuzz outputs generated domain variations in plain text format:
```
g0ogle.com
googel.com
google.net
secure-google.com
googlle.com
goоgle.com  # Cyrillic 'о'
...
```

With status checking enabled:
```
g0ogle.com, available
googel.com, registered
google.net, parked
secure-google.com, available
...
```

## Algorithm Details

### Character Substitution Mappings
- `o→0`, `l→1`, `i→1`, `e→3`, `a→@`, `s→$`, `g→9`, `b→6`, `t→7`, `z→2`

### QWERTY Keyboard Layout
Adjacent key mappings based on standard QWERTY layout for realistic typos.

### Unicode Homoglyphs
Extensive Unicode character mappings including:
- **Cyrillic**: `а` (U+0430) vs `a` (U+0061)
- **Greek**: `α` (U+03B1) vs `a` (U+0061)
- **Extended**: Full Unicode homoglyph database

### Homophone Dictionary
Common sound-alike word pairs:
- `right→write,rite`
- `sea→see,c`
- `won→one,1`
- `to→two,too,2`

## Performance

DomFuzz is optimized for high performance:
- **Fast generation**: 1000s of variations per second
- **Memory efficient**: HashSet deduplication
- **Concurrent network checks**: Async domain status verification
- **Scalable**: Handles large domain lists efficiently

## Security Considerations

This tool is intended for:
- ✅ **Defensive security research**
- ✅ **Domain monitoring and protection**
- ✅ **Threat intelligence analysis**  
- ✅ **Educational purposes**

**Do not use for malicious activities.** Users are responsible for compliance with applicable laws and ethical guidelines.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## References

- [URLCrazy](https://github.com/urbanadventurer/urlcrazy) - Original Ruby implementation
- [dnstwist](https://github.com/elceef/dnstwist) - Python domain fuzzing tool
- [URLInsane](https://github.com/rangertaha/urlinsane) - Go domain fuzzing tool
- [DomainFuzz](https://github.com/monkeym4ster/DomainFuzz) - Python domain fuzzing tool
- [Unicode Homoglyph Research](https://www.unicode.org/reports/tr39/)

## Changelog

### v0.1.1
- Added 13 new fuzzing algorithms from URLCrazy, dnstwist, URLInsane, and DomainFuzz
- Organized algorithms into logical groups
- Improved CLI with help groupings
- Enhanced Unicode support
- Added comprehensive documentation

### v0.1.0
- Initial release with basic typosquatting algorithms