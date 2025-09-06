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

The `lookalike` bundle is the default transformation set, specifically designed to generate domains that can fool users through visual deception. This bundle combines the four most effective transformation types that attackers commonly use in phishing campaigns and typosquatting attacks.

**The lookalike bundle includes:**

#### 🔢 1337speak (Leetspeak)
Replaces letters with visually similar numbers and symbols using internet culture conventions:
- **Core mappings**: o→0 (most common), l→1, e→3, a→4, s→5, g→9, b→6, t→7, z→2
- **Intelligence applied**: Maximum 40% substitution, respects domain length, prioritizes high-impact changes
- **Real examples**: google.com → g00gle.com, g0ogle.com, goog1e.com, 9oogle.com

#### ⌨️ Misspelling
Comprehensive typing error simulation modeling natural user mistakes:
- **Error types**: Character deletion, insertion, transposition, substitution, vowel swapping
- **Keyboard awareness**: QWERTY-based adjacent key errors, frequency-weighted placement
- **Real examples**: google.com → googlle.com (insertion), gogle.com (deletion), googel.com (transposition)

#### 👆 Fat-finger
Models accidental keypresses from imprecise typing or mobile input:
- **Mechanisms**: Character doubling, adjacent key insertion, multiple finger errors
- **QWERTY modeling**: Horizontal, vertical, and diagonal key adjacency
- **Real examples**: google.com → gooogle.com (doubling), googke.com (adjacent l→k)

#### 🌐 Mixed-encodings (Homograph Attacks)
Advanced Unicode homoglyph attacks using visually identical characters from different scripts. Enhanced with comprehensive character mappings based on IronGeek's homoglyph generator research:

- **Extensive character coverage**: 60+ Unicode characters per letter with mappings from Cyrillic, Greek, Latin Extended, Armenian, Cherokee, and other scripts
- **Attack vectors**: Single, double, and triple character substitutions with intelligent positioning
- **Script mixing**: Cyrillic (а, е, о, р), Greek (α, β, γ, δ), Fullwidth (ａ, ｂ, ｃ), Accented Latin (À, É, ü)
- **Dangerous examples**: 
  - google.com → gооgle.com (Cyrillic 'о' characters)
  - amazon.com → аmazon.com (Cyrillic 'а')
  - paypal.com → раypal.com (Cyrillic 'р')
  - microsoft.com → microsοft.com (Greek 'ο')
- **Technical sophistication**: Punycode encoding creates valid IDN domains that appear identical in browsers
- **Enhanced detection resistance**: Multiple substitution combinations with realistic character distribution
- **Real-world impact**: Domains appear completely identical but resolve to attacker-controlled IPs



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

### 🔤 Advanced Character Manipulation
Beyond the lookalike bundle, additional character-level techniques:

#### 💾 Bitsquatting
Simulates single bit-flip errors from hardware failures, memory corruption, or cosmic ray strikes:
- **Mechanism**: Flips individual bits in ASCII characters (8-bit representation)
- **Examples**: 'o' (0x6F) → 'g' (0x67), 'e' (0x65) → 'a' (0x61)
- **Attack scenarios**: Memory corruption, hardware failures, electromagnetic interference
- **Real examples**: google.com → gmogle.com, foogle.com (various bit-flips)

```bash
cargo run -- -t bitsquatting example.com
```





### 🗣️ Phonetic/Semantic
Sound and meaning-based transformations that exploit language patterns:

#### 🔊 Homophones
Replaces words with sound-alike alternatives having different spellings:
- **Categories**: Direct homophones (to/two), phonetic spelling (phone→fone), silent letters (know→no)
- **Examples**: paypal.com → paypall.com, security.com → sekurity.com
- **Effectiveness**: Targets non-native speakers, voice-to-text systems

#### 🧠 Cognitive
Exploits semantic associations and business terminology confusion:
- **Substitution types**: Synonyms (secure→safe), industry terms (login→signin), concept overlap (mail→email)
- **Psychology**: Leverages mental associations, "close enough" feeling
- **Examples**: paypal.com → payfriend.com, microsoft.com → microsoftware.com

#### 📝 Singular/Plural
Converts between grammatical forms exploiting naming convention uncertainty:
- **Patterns**: Regular plurals (file→files), irregular (child→children), compound words
- **Business impact**: Many legitimate sites exist in both forms
- **Examples**: amazon.com → amazone-products.com, microsoft.com → microsoftservices.com

```bash
cargo run -- -t homophones,cognitive,singular-plural facebook.com
```

### 🔢 Number/Word Substitution
Exploits variations in numeric representation:

#### 🔢 Cardinal Substitution
Converts between digits and written numbers:
- **Bidirectional**: 1↔one, 2↔two, 4↔four (including homophone 'for')
- **Special contexts**: Versioning (v1→vone), ranking (top5→topfive), quantities (buy2→buytwo)
- **Examples**: 1password.com → onepassword.com, 4chan.org → fourchan.org

#### 🥇 Ordinal Substitution
Converts between numeric and written ordinal forms:
- **Patterns**: 1st↔first, 2nd↔second, 3rd↔third
- **Business use**: Priority services (1stchoice→firstchoice), sequences (2ndround→secondround)
- **Examples**: 21stcentury.com → twentyfirstcentury.com, 3rdpartysoftware.com → thirdpartysoftware.com

```bash
cargo run -- -t cardinal-substitution,ordinal-substitution first1.com
```

### 🏗️ Structure Manipulation
Domain structure and format modifications:

#### 🔄 Word Swapping
Reorders components in compound domain names while maintaining brand elements:
- **Patterns**: Two-word reversal (mybank→bankmy), multi-word rotation, action-object swaps
- **Psychology**: Users focus on familiar words, not exact order
- **Examples**: paypalcredit.com → creditpaypal.com, microsoftoffice.com → officemicrosoft.com

#### ➖ Hyphenation
Manipulates hyphen usage through insertion, removal, and substitution:
- **Techniques**: Hyphen insertion (google→goo-gle), removal (my-bank→mybank), character substitution (_→-)
- **Effectiveness**: Many legitimate sites exist with/without hyphens
- **Examples**: paypal.com → pay-pal.com, facebook.com → face-book.com

#### 📍 Subdomain Injection
Strategic subdomain manipulation and dot placement:
- **Dot insertion**: g.oogle.com, goo.gle.com
- **Dot omission**: mail.google.com → mailgoogle.com
- **Dot-hyphen substitution**: sub.domain.com → sub-domain.com

```bash
cargo run -- -t word-swap,hyphenation,dot-insertion google.com
```

### ⚠️ System Fault
Hardware and system error transformations:
- **Bitsquatting**: Single bit-flip transformations simulating hardware memory errors, cosmic ray hits, or transmission corruption

```bash
cargo run -- -t system-fault example.com
```

### 🌍 Domain Extensions & Branding
TLD manipulation and brand-based deception:

#### 🌐 TLD Variations
Alternative top-level domain substitutions:
- **Common swaps**: .com→.net/.org/.co/.io, country codes (.co.uk, .de, .fr)
- **Examples**: google.com → google.net, google.org, google.co

#### 🏢 Combosquatting
Combines target domains with common dictionary words for enhanced legitimacy:
- **Word categories**: Security (secure-, safe-), services (-support, -help), authority (official-, real-)
- **Psychology**: Creates perception of enhanced security or official relationship
- **Examples**: google.com → securegoogle.com, paypal.com → paypallogin.com

#### 🎯 Brand Confusion
Adds brand-related terms to exploit trust in established names:
- **Techniques**: Authority prefixes (official-, verified-), service extensions (-support, -center)
- **Examples**: microsoft.com → officialmicrosoft.com, amazon.com → amazon-support.com

#### 🔤 Domain Prefix/Suffix
Common prefix and suffix additions:
- **Prefixes**: my-, the-, secure-, get-
- **Suffixes**: -app, -online, -secure, -official
- **Examples**: google.com → mygoogle.com, google-secure.com

```bash
cargo run -- -t tld-variations,combosquatting,brand-confusion amazon.com
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
- [IronGeek Homoglyph Attack Generator](https://www.irongeek.com/homoglyph-attack-generator.php) - Comprehensive homoglyph research and generator
- [Unicode Homoglyph Research](https://www.unicode.org/reports/tr39/)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed version history and release notes.