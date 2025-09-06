# DomFuzz

A comprehensive domain name fuzzing tool written in Rust for generating typosquatting variations used in cybersecurity research and defensive purposes.

## Overview

DomFuzz generates domain name variations using advanced typosquatting techniques commonly employed in phishing campaigns and cybersquatting transformations. The tool implements transformations from leading domain fuzzing tools like URLCrazy, dnstwist, URLInsane, and DomainFuzz, providing comprehensive coverage of domain manipulation techniques.

## Features

- **15+ fuzzing transformations** organized into logical groups
- **Smart defaults** using the `lookalike` bundle (15 character-level visual similarity transformations)
- **Network status checking** for domain availability
- **Customizable output** with variation limits
- **Dictionary-based combosquatting** with custom wordlists
- **Unicode and international** character support
- **High performance** Rust implementation with true streaming

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

DomFuzz organizes its transformations into logical groups for easier usage:

## Transformation Bundles

For convenience, DomFuzz provides pre-configured bundles that group related transformations:

### 👀 Lookalike Bundle
**Character-level transformations that create visually similar domains**

The `lookalike` bundle includes all transformations that focus on character-level substitutions and visual confusion attacks:

**Basic Character Substitutions:**
- `1337speak` - Leetspeak character substitutions with realistic combinations (o→0, l→1, e→3, a→@, s→$)
- `misspelling` - Character insertion, deletion, transposition, keyboard typos, vowel swaps (with combinations)  
- `fat-finger` - Character doubling, adjacent-keys substitution, and adjacent-keys insertion (combinations)

**Unicode/Script Variations:**
- `mixed-encodings` - Visually similar characters (a→α), Unicode/Punycode, multiple writing systems, extended character set substitutions, extensive Cyrillic lookalikes

**Advanced Character Manipulation:**



**Usage:**
```bash
# Use the complete lookalike bundle
cargo run -- -t lookalike google.com

# Combine bundle with individual transformations
cargo run -- -t lookalike,tld-variations example.com

# Lookalike bundle in single-transformation mode
cargo run -- -t lookalike -1 paypal.com
```

This bundle is particularly effective for:
- 🎯 **Phishing detection** - Identifies domains designed to fool users
- 🛡️ **Brand protection** - Comprehensive visual similarity coverage
- 🔍 **Threat intelligence** - Character-level domain mutations
- 📱 **Mobile security** - Targets small-screen typos and rendering issues

### ⚠️ System Fault Bundle
**Hardware and system error transformations**

The `system-fault` bundle includes transformations that simulate errors caused by hardware failures, memory corruption, or transmission errors:

**Hardware/System Errors:**
- `bitsquatting` - Single bit-flip transformations

**Usage:**
```bash
# Use the system-fault bundle
cargo run -- -t system-fault google.com

# Combine with other bundles
cargo run -- -t lookalike,system-fault example.com
```

This bundle is particularly effective for:
- 🔧 **Infrastructure testing** - Identifies domains that could result from hardware errors
- 🛡️ **DNS security** - Tests resilience against bit-flip attacks
- 🔍 **Attack simulation** - Models sophisticated bitsquatting campaigns
- 📡 **Network security** - Simulates transmission corruption scenarios

### 🔤 Basic Typos
Common typing mistakes and simple character errors:
- **Leetspeak Substitution**: `o→0`, `l→1`, `e→3`, etc.
- **Misspellings**: Character insertion, deletion, transposition, omission, addition, double-char-replacement
- **Fat Finger**: Double characters (`google→gooogle`), adjacent-keys substitution, and adjacent-keys insertion (with combinations)  
- **Keyboard Proximity**: Adjacent key typos based on QWERTY layout

```bash
cargo run -- --1337speak --misspelling google.com
```

### 🔧 Character Manipulation
Advanced character-level transformation techniques:
- **Bitsquatting**: Single bit-flip transformations


```bash
cargo run -- --fat-finger example.com
```

### 🌐 Unicode/Script Attacks
International character confusion transformations:
- **Mixed Encodings**: Visually similar characters (`a→α`), Unicode/Punycode transformations, Cyrillic + Latin character mixing, 160k+ character homoglyph support, extensive Cyrillic substitutions

```bash
cargo run -- --mixed-encodings paypal.com
```

### 🗣️ Phonetic/Semantic
Sound and meaning-based transformations:
- **Homophones**: Sound-alike word replacements (`right→write`)
- **Vowel Swapping**: Vowel interchange (`a↔e`, `i↔o`)
- **Cognitive**: Semantic word confusion transformations
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
- **Subdomain Injection**: Internal dot insertion
- **Dot Insertion/Omission**: Dot manipulation
- **Dot/Hyphen Substitution**: Dot-hyphen interchange

```bash
cargo run -- --hyphenation --dot-insertion google.com
```

### ⚠️ System Fault
Hardware and system error transformations:
- **Bitsquatting**: Single bit-flip transformations simulating hardware memory errors, cosmic ray hits, or transmission corruption

```bash
cargo run -- -t system-fault example.com
```

### 🌍 Domain Extensions
TLD and branding manipulation:
- **TLD Variations**: Alternative top-level domains
- **International TLD**: IDN TLD variations (`.com→.көм`)
- **Wrong SLD**: Incorrect second-level domains (`.co.uk→.co.gov.uk`)
- **Combosquatting**: Keyword combination transformations
- **Brand Confusion**: Authority prefixes/suffixes (`secure-`, `-official`)
- **Domain Prefix/Suffix**: Common domain extensions

```bash
cargo run -- --tld-variations --brand-confusion --combosquatting amazon.com
```

## Usage Examples

### Basic Usage
```bash
# Generate lookalike variations (default behavior - uses lookalike bundle)
cargo run -- example.com

# Explicitly specify lookalike bundle  
cargo run -- -t lookalike example.com

# Use all transformations
cargo run -- -t all example.com

# Use specific transformations
cargo run -- -t char-sub,keyboard example.com

# Limit output and check status
cargo run -- --max-variations 50 --check-status example.com
```

### Advanced Usage
```bash
# Custom dictionary for combosquatting
cargo run -- --combosquatting --dictionary /path/to/wordlist.txt target.com

# Focus on international transformations
cargo run -- --cyrillic-comprehensive --idn-homograph --intl-tld example.com

# Phonetic and semantic transformations only
cargo run -- --homophones --cognitive --singular-plural rightmove.com
```

### Real-World Examples

**Comprehensive Visual Similarity Analysis:**
```bash
# Use lookalike bundle for complete character-level coverage
cargo run -- -t lookalike --max-variations 100 --check-status google.com
```

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

See [CHANGELOG.md](CHANGELOG.md) for detailed version history and release notes.