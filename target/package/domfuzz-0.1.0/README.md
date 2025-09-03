# DomFuzz

A Rust CLI tool for generating domain name variations using various typosquatting techniques. This tool is designed for security research and defensive purposes to identify potential typosquatted domains.

## Features by Category

### 🔠 **Character-Level Attacks**
- **Character Substitution**: Replace characters with visually similar ones (o→0, l→1, etc.)
- **Homoglyphs**: Basic Unicode characters that look identical to ASCII letters
- **IDN Homograph Attacks**: Advanced Unicode/Punycode attacks using international scripts
- **Mixed Script Attacks**: Combine characters from different language scripts (Cyrillic + Latin)
- **Extended Unicode Homoglyphs**: Leverage the full 160k+ Unicode character space

### ⌨️ **Input-Based Attacks**
- **Keyboard Proximity**: Exploit adjacent key typing errors (QWERTY, QWERTZ, AZERTY)
- **Misspelling Variations**: Common typos through insertion, deletion, and transposition
- **Repetition**: Double letters to simulate typing mistakes
- **Character Omission**: Strategic character removal patterns

### 🌐 **Domain Structure Attacks**
- **TLD Variations**: Test different top-level domains including internationalized TLDs
- **Subdomain Injection**: Create misleading subdomain structures
- **Word Part Swapping**: Rearrange parts of the domain name
- **Vowel Swapping**: Strategic vowel substitutions
- **Hyphenation**: Insert hyphens at strategic positions

### 🏢 **Brand Confusion Attacks**
- **Combosquatting**: Combine brands with common keywords (most dangerous technique)
- **Brand Confusion**: Strategic prefixes/suffixes creating authority confusion
- **Addition Variations**: Append letters/numbers to domain names

### ⚙️ **Technical Attacks**
- **Bitsquatting**: Exploit bit-flip errors in computer memory during DNS resolution

## Installation

```bash
git clone <repository-url>
cd domfuzz
cargo build --release
```

## Usage

```bash
# Generate all types of variations (default)
./target/release/domfuzz example.com

# Generate only character substitutions and TLD variations
./target/release/domfuzz --char-sub --tld-variations example.com

# Limit the number of variations
./target/release/domfuzz --max-variations 50 example.com

# Enable all variation types explicitly
./target/release/domfuzz --all example.com
```

### Command Line Options

#### 🔠 Character-Level Attacks
- `--char-sub`: Character substitution variations (o→0, l→1, etc.)
- `--homoglyphs`: Basic Unicode homoglyph variations  
- `--idn-homograph`: Advanced IDN homograph attacks (Unicode/Punycode)
- `--mixed-script`: Mixed script attacks (Cyrillic + Latin combinations)
- `--extended-unicode`: Extended Unicode homoglyphs (160k+ characters)

#### ⌨️ Input-Based Attacks
- `--keyboard`: Keyboard proximity variations (QWERTY, QWERTZ, AZERTY)
- `--misspellings`: Misspelling variations (insertion, deletion, transposition)
- `--repetition`: Repetition variations (double letters)
- `--omission`: Character omission variations

#### 🌐 Domain Structure Attacks
- `--tld-variations`: Different TLD variations
- `--intl-tld`: Internationalized TLD variations
- `--subdomain`: Subdomain injection variations
- `--word-swap`: Word part swapping variations
- `--vowel-swap`: Vowel swapping variations
- `--hyphenation`: Hyphenation variations

#### 🏢 Brand Confusion Attacks
- `--combosquatting`: Combosquatting with common keywords
- `--brand-confusion`: Brand confusion techniques (prefixes/suffixes)
- `--addition`: Addition variations (append letters/numbers)

#### ⚙️ Technical Attacks
- `--bitsquatting`: Bitsquatting (bit-flip variations)

#### 📁 Configuration Options
- `--dictionary <FILE>`: Path to dictionary file for combosquatting
- `--all`: Enable all variation types
- `--max-variations <N>`: Limit output to N variations (default: 1000)

If no specific variation flags are provided, all types are enabled by default.

## Examples

### Basic Usage
```bash
# Generate all types of variations (default)
$ ./target/release/domfuzz google.com | head -10
g00gle.com
goo9le.com
goog1e.com
googl3.com
google.net
google.org
google.co
googlе.com
gogole.com
goolge.com
```

### Character-Level Attacks
```bash
# Basic character substitutions
$ ./target/release/domfuzz --char-sub paypal.com | head -3
p@ypal.com
payp@l.com
paypa1.com

# Advanced IDN homograph attacks (most dangerous)
$ ./target/release/domfuzz --idn-homograph amazon.com | head -5
аmazon.com      # Cyrillic 'а' instead of Latin 'a'
amazon.сom      # Cyrillic 'с' instead of Latin 'c'  
amаzon.com      # Multiple Cyrillic substitutions
amazon​.com      # Contains invisible zero-width space
‮amazon.com     # Right-to-left override attack

# Mixed script combinations
$ ./target/release/domfuzz --mixed-script google.com | head -3
gооgle.com      # Mixed Cyrillic and Latin 'o'
goοgle.com      # Mixed Greek and Latin 'o'
gοοgle.com      # Multiple Greek omicrons
```

### Input-Based Attacks
```bash
# Keyboard proximity errors (supports QWERTY, QWERTZ, AZERTY)
$ ./target/release/domfuzz --keyboard amazon.com | head -5
ajazon.com
akazon.com
amaaon.com
amason.com
amaxon.com

# Character omission patterns
$ ./target/release/domfuzz --omission microsoft.com | head -3
icrosoft.com
mcrosoft.com
micosoft.com
```

### Domain Structure Attacks  
```bash
# Internationalized TLD variations
$ ./target/release/domfuzz --intl-tld paypal.com | head -5
paypal.ком        # .com in Cyrillic
paypal.中国       # .com in Chinese
paypal.コム       # .com in Japanese
paypal.한국       # Korea TLD in Hangul
paypal.рф         # Russia TLD in Cyrillic

# Hyphenation variations
$ ./target/release/domfuzz --hyphenation google.com
g-oogle.com
go-ogle.com
goo-gle.com
goog-le.com
googl-e.com
```

### Brand Confusion Attacks
```bash
# Combosquatting (most used in real attacks)
$ ./target/release/domfuzz --combosquatting paypal.com | head -5
paypal-support.com
paypalsupport.com
support-paypal.com
secure-paypal.com
paypal-login.com

# Brand confusion with authority terms
$ ./target/release/domfuzz --brand-confusion amazon.com | head -5
www-amazon.com
secure-amazon.com
official-amazon.com
amazon-official.com
amazon-corp.com
```

### Technical Attacks
```bash
# Bitsquatting (exploits hardware bit-flip errors)
$ ./target/release/domfuzz --bitsquatting google.com | head -5
foogle.com      # g→f (single bit difference)
coogle.com      # g→c (single bit difference)
eoogle.com      # g→e (single bit difference)
ggogle.com      # o→g (single bit difference)
gkogle.com      # o→k (single bit difference)
```

## Attack Categories Explained

### 🔠 **Character-Level Attacks**

#### Character Substitution
Replaces common characters with visually similar alternatives:
- `o` ↔ `0`, `l` ↔ `1`, `i` ↔ `1`
- `e` → `3`, `a` → `@`, `s` → `$`
- `g` → `9`, `b` → `6`, `t` → `7`, `z` → `2`

#### Basic Homoglyphs
Uses basic Unicode characters that look identical to ASCII letters but have different code points:
- **Cyrillic**: `а` (U+0430) vs `a` (U+0061)
- **Greek**: `ο` (U+03BF) vs `o` (U+006F)
- **Common substitutions**: Cyrillic and Greek scripts that appear identical to Latin letters

#### IDN Homograph Attacks ⚠️ **Most Dangerous**
Advanced Unicode/Punycode attacks using internationalized domain infrastructure:
- **Right-to-Left Override (U+202E)**: Exploits bidirectional text rendering
- **Invisible characters**: Zero-width spaces, joiners, and other invisible Unicode characters
- **Punycode encoding**: `xn--` prefixed domains that decode to Unicode attacks
- **Multiple character combinations**: Combines multiple homoglyphs in sophisticated patterns

#### Mixed Script Attacks
Combines characters from different language scripts in the same domain:
- **Cyrillic + Latin**: `gооgle.com` (mixed 'o' characters)
- **Greek + Latin**: `goοgle.com` (Greek omicron + Latin)
- **Directional markers**: Left-to-right and right-to-left Unicode markers

#### Extended Unicode Homoglyphs
Leverages the full 160,000+ Unicode character space:
- **Mathematical scripts**: `𝒶mazon.com` (mathematical script 'a')
- **Regional scripts**: Armenian, Georgian, Cherokee, Arabic contextual forms
- **Normalization attacks**: Different Unicode forms of the same visual character

### ⌨️ **Input-Based Attacks**

#### Keyboard Proximity
Exploits natural typing errors based on keyboard layouts:
- **QWERTY layout**: `q↔w`, `s↔d`, `f↔g`, `j↔k`
- **QWERTZ layout**: `y↔z`, `q↔w` (German/European)
- **AZERTY layout**: `a↔q`, `w↔z` (French)
- **Example**: `paypal.com` → `payoal.com` (p→o adjacent keys)

#### Misspelling Variations
Common typing errors and typos:
- **Insertion**: Add characters at various positions
- **Deletion**: Remove individual characters (omission patterns)
- **Transposition**: Swap adjacent characters

#### Repetition Variations  
Doubles letters to simulate common typing mistakes:
- **Technique**: Double each character in the domain
- **Examples**: `google.com` → `gooogle.com`, `facebook.com` → `faacebook.com`

### 🌐 **Domain Structure Attacks**

#### TLD Variations
Tests different top-level domains:
- **Generic TLDs**: com, net, org, biz, info
- **Country codes**: us, uk, ca, de, fr, ru, cn, jp, au
- **New TLDs**: app, dev, tech, online, site
- **Free TLDs**: tk, ml, ga, cf

#### Internationalized TLD Variations
Uses Unicode and country-specific TLDs:
- **Cyrillic TLDs**: `.ком` (.com), `.рф` (Russia)
- **Chinese TLDs**: `.中国` (China), `.公司` (.com)
- **Arabic TLDs**: `.السعودية` (Saudi Arabia)
- **Mixed script TLDs**: `com.ау` (Cyrillic 'au')

#### Word Part Swapping
Rearranges parts of the domain name:
- **Halves**: Swap first and second half
- **Thirds**: Swap first and last third
- **Sliding windows**: Swap characters within windows

#### Vowel Swapping
Strategic vowel substitutions:
- **Common swaps**: `a↔e`, `i↔o`, `u↔o`
- **Examples**: `paypal.com` → `paypel.com`, `google.com` → `guggle.com`

#### Hyphenation
Insert hyphens at strategic positions:
- **Examples**: `google.com` → `g-oogle.com`, `paypal.com` → `pay-pal.com`
- **Deception**: Creates apparent word separation

#### Subdomain Injection
Creates misleading subdomain structures:
- **Technique**: Insert dots at various positions
- **Example**: `paypal.com` → `pay.pal.com`, `microsoft.com` → `micro.soft.com`
- **Deception**: Creates appearance of legitimate subdomains

### 🏢 **Brand Confusion Attacks**

#### Combosquatting ⚠️ **Most Used in Real Attacks**
Combines legitimate brands with common keywords:
- **Top keywords**: "support", "secure", "login", "pay", "help", "service"
- **Examples**: 
  - `paypal-support.com`
  - `google-login.com` 
  - `amazon-security.com`
- **Research**: 60%+ of real typosquatting attacks use combosquatting (Akamai 2024)

#### Brand Confusion
Strategic prefixes/suffixes creating authority confusion:
- **Authority prefixes**: "www", "secure", "official", "my", "admin"  
- **Service suffixes**: "-app", "-online", "-portal", "-center", "-pro"
- **Examples**: `secure-amazon.com`, `paypal-official.com`

#### Addition Variations
Appends characters to domain names:
- **Letters**: `google.com` → `googlea.com`
- **Numbers**: `facebook.com` → `facebook1.com`
- **Combinations**: `amazon2024.com`

### ⚙️ **Technical Attacks**

#### Bitsquatting
Exploits bit-flip errors in computer memory during DNS resolution:
- **Technique**: XOR each character with bit masks (1, 2, 4, 8, 16, 32, 64, 128)
- **Example**: `google.com` → `foogle.com` (g→f is a single bit difference)
- **Sophistication**: Exploits hardware-level memory errors and cosmic ray interference
- **Target**: High-traffic domains where bit-flips are more likely to be noticed

## Security Considerations

This tool is intended for:
- Security research
- Defensive domain monitoring
- Identifying potential typosquatting attempts
- Brand protection

**Do not use this tool for malicious purposes such as:**
- Registering typosquatted domains
- Phishing campaigns
- Brand impersonation
- Any illegal activities

## Author

**Albert Hui** <albert@securityronin.com>

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

This tool is provided for educational and defensive security purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.