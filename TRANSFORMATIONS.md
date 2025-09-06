# Domain Transformation Guide

DomFuzz implements 22 sophisticated domain transformation algorithms that simulate how attackers create typosquatting domains. This document provides detailed explanations and examples for each transformation type.

## Core Transformations

### 1. 1337speak (Leet Speak)
**Purpose**: Simulates character substitution attacks using numbers that visually resemble letters.

**Method**: Replaces letters with visually similar numbers:
- `e` → `3`
- `t` → `7` 
- `s` → `5`
- `o` → `0`
- `a` → `4`
- `i` → `1`
- `g` → `9`

**Examples** (for `google.com`):
- `g00gle.com` (o→0)
- `googl3.com` (e→3)
- `9oogle.com` (g→9)
- `goog1e.com` (l→1)

### 2. Misspelling
**Purpose**: Simulates common typing errors including transposition, insertion, deletion, and substitution.

**Method**: 
- **Transposition**: Swap adjacent characters (`test.com` → `tset.com`)
- **Deletion**: Remove a character (`test.com` → `tst.com`)
- **Insertion**: Add a character at random position (`test.com` → `atest.com`)
- **Substitution**: Replace character with another letter (`test.com` → `rest.com`)

**Examples** (for `google.com`):
- `goolge.com` (transposition: l↔g)
- `goole.com` (deletion: g removed)
- `agoogle.com` (insertion: a added)
- `foogle.com` (substitution: g→f)

### 3. Fat-finger (QWERTY Adjacent Keys)
**Purpose**: Simulates keyboard layout-based typing errors where users hit adjacent keys.

**Method**: 
- **Key substitution**: Replace with QWERTY-adjacent keys
- **Key repetition**: Double characters (`google.com` → `gooogle.com`)
- **Adjacent insertion**: Insert adjacent keys before/after characters

**QWERTY Layout Mapping**:
```
q w e r t y u i o p
 a s d f g h j k l
  z x c v b n m
```

**Examples** (for `google.com`):
- `hoogle.com` (g→h, adjacent key)
- `goigle.com` (o→i, adjacent key)
- `googke.com` (l→k, adjacent key)
- `gooogle.com` (repeated o)

### 4. Mixed-encodings (Homograph Attack)
**Purpose**: Uses Unicode characters that look identical to ASCII but have different code points.

**Method**: Replaces ASCII characters with visually identical Unicode characters:
- Latin `o` (U+006F) → Cyrillic `о` (U+043E)
- Latin `e` (U+0065) → Cyrillic `е` (U+0435)
- Latin `a` (U+0061) → Cyrillic `а` (U+0430)
- And many other lookalikes from Greek, Cyrillic, and other scripts

**Examples** (for `google.com`):
- `gооgle.com` (ASCII o → Cyrillic о)
- `googlе.com` (ASCII e → Cyrillic е)
- `gοogle.com` (ASCII o → Greek ο)

### 5. Bitsquatting
**Purpose**: Simulates bit-flip errors that can occur in DNS requests due to hardware failures or cosmic rays.

**Method**: Flips individual bits in ASCII characters:
- `g` (0x67) → `e` (0x65) - bit flip
- `o` (0x6F) → `n` (0x6E) - bit flip
- `l` (0x6C) → `h` (0x68) - bit flip

**Examples** (for `google.com`):
- `engle.com` (g→e via bit flip)
- `gnngle.com` (o→n via bit flip)
- `goohhe.com` (l→h via bit flip)

### 6. Word-swap
**Purpose**: Swaps individual words in multi-word domains.

**Method**: For domains with multiple words (separated by hyphens or CamelCase), swaps their positions.

**Examples**:
- `secure-bank.com` → `bank-secure.com`
- `myCompany.com` → `companyMy.com`
- `first-second-third.com` → `third-second-first.com`

### 7. Homophones
**Purpose**: Replaces words with words that sound the same but are spelled differently.

**Method**: Uses a dictionary of common homophones:
- `to` ↔ `two` ↔ `too`
- `for` ↔ `four`  
- `buy` ↔ `by` ↔ `bye`
- `there` ↔ `their` ↔ `they're`

**Examples**:
- `buynow.com` → `bynow.com`
- `forthem.com` → `fourthemselves.com`

### 8. Singular-plural
**Purpose**: Converts between singular and plural forms of words.

**Method**: 
- Adds/removes common plural suffixes (`s`, `es`, `ies`)
- Handles irregular plurals (`child`/`children`, `mouse`/`mice`)

**Examples**:
- `book.com` → `books.com`
- `company.com` → `companies.com`
- `mouse.com` → `mice.com`

### 9. Dot-insertion
**Purpose**: Inserts dots in unexpected places within the domain.

**Method**: Inserts `.` characters at various positions in the domain name.

**Examples** (for `google.com`):
- `go.ogle.com`
- `goo.gle.com`
- `g.oogle.com`

### 10. Dot-omission  
**Purpose**: Removes dots from domains that should have them.

**Method**: Removes subdomain separators.

**Examples**:
- `mail.google.com` → `mailgoogle.com`
- `www.example.com` → `wwwexample.com`

### 11. Cardinal-substitution
**Purpose**: Replaces spelled-out numbers with digits.

**Method**: Converts written numbers to numerals:
- `one` → `1`
- `two` → `2`
- `three` → `3`
- `four` → `4`
- `five` → `5`

**Examples**:
- `onetwo.com` → `12.com`
- `threefour.com` → `34.com`

### 12. Ordinal-substitution
**Purpose**: Replaces spelled-out ordinal numbers with their numeric equivalents.

**Method**: Converts ordinal words to numbers:
- `first` → `1st`
- `second` → `2nd`
- `third` → `3rd`
- `fourth` → `4th`

**Examples**:
- `firstbank.com` → `1stbank.com`
- `secondchance.com` → `2ndchance.com`

### 13. TLD-variations
**Purpose**: Replaces the top-level domain with similar or commonly confused TLDs.

**Method**: Substitutes TLD with:
- Similar TLDs (`.com` ↔ `.co` ↔ `.org`)
- Country-specific TLDs (`.com` → `.co.uk`, `.de`, `.fr`)
- New gTLDs (`.app`, `.tech`, `.online`)

**Examples** (for `google.com`):
- `google.co`
- `google.org`
- `google.net`
- `google.co.uk`

### 14. Brand-confusion
**Purpose**: Creates variations that could confuse users about brand association.

**Method**: 
- Adds common brand prefixes (`my`, `the`, `official`)
- Adds brand suffixes (`online`, `app`, `secure`)
- Combines with competitor names

**Examples** (for `google.com`):
- `mygoogle.com`
- `googlesecure.com`
- `officialgoogle.com`

### 15. International TLD (intl-tld)
**Purpose**: Uses internationalized domain names and country-specific TLDs.

**Method**: 
- Applies IDN encoding (Punycode)
- Uses country-specific TLD patterns
- Combines with local language variations

**Examples**:
- `google.中国` (China)
- `google.рф` (Russia)
- `google.台湾` (Taiwan)

### 16. Cognitive
**Purpose**: Exploits cognitive biases and mental shortcuts users make when typing URLs.

**Method**:
- Creates phonetically similar domains
- Uses common abbreviations and contractions
- Exploits muscle memory patterns

**Examples** (for `google.com`):
- `goggle.com` (common misspelling)
- `googel.com` (common transposition)
- `gogle.com` (dropped letter)

### 17. Dot-hyphen Substitution
**Purpose**: Replaces dots with hyphens and vice versa.

**Method**: 
- `.` → `-`
- `-` → `.`

**Examples**:
- `sub.domain.com` → `sub-domain.com`
- `my-site.com` → `my.site.com`

### 18. Subdomain Injection
**Purpose**: Adds misleading subdomains to create official-looking domains.

**Method**: Prepends common subdomain patterns:
- `www.` → `www-[target].com`
- `mail.` → `mail-[target].com`  
- `secure.` → `secure-[target].com`

**Examples** (for `google.com`):
- `www-google.badsite.com`
- `mail-google.phishing.com`
- `secure-google.fake.com`

### 19. Combosquatting
**Purpose**: Combines the target domain with common dictionary words.

**Method**: 
- Prepends dictionary words (`secure-google.com`)
- Appends dictionary words (`google-login.com`)
- Uses high-frequency words like: secure, login, mail, support, help

**Examples** (for `google.com`):
- `securegoogle.com`
- `googlelogin.com`
- `googlesupport.com`
- `mailgoogle.com`

### 20. Wrong Second-Level Domain (wrong-sld)
**Purpose**: Uses correct TLD but wrong second-level domain.

**Method**: Keeps the TLD but modifies the main domain part.

**Examples** (for `google.com`):
- `goggle.com`
- `googel.com`
- `gooogle.com`

### 21. Domain-prefix
**Purpose**: Adds common prefixes to domain names.

**Method**: Prepends frequently used prefixes:
- `my-`
- `the-`
- `get-`
- `new-`
- `old-`
- `real-`

**Examples** (for `google.com`):
- `my-google.com`
- `the-google.com`
- `get-google.com`

### 22. Domain-suffix  
**Purpose**: Adds common suffixes to domain names.

**Method**: Appends frequently used suffixes:
- `-app`
- `-online`
- `-secure` 
- `-login`
- `-support`
- `-help`

**Examples** (for `google.com`):
- `google-app.com`
- `google-online.com`
- `google-secure.com`

## Combination Strategies

### Lookalike Bundle (Default)
When no specific transformation is specified, DomFuzz uses the "lookalike" bundle that combines the most effective transformations:

1. **1337speak** - Character substitution with numbers
2. **Misspelling** - Common typing errors  
3. **Fat-finger** - QWERTY-adjacent key errors
4. **Mixed-encodings** - Unicode homograph attacks

This combination provides comprehensive coverage of the most common typosquatting techniques used by attackers.

### Combo Mode (`--combo`)
The combo mode applies random sequences of transformations to create more sophisticated variations:

- Applies 2-4 transformations per domain
- Uses weighted selection (some transformations more likely)
- Avoids conflicting combinations
- Generates more realistic attack scenarios

**Example combo transformations** (for `google.com`):
- `9o0gl3.com` (1337speak: g→9, o→0, e→3)
- `hgoogle.com` (fat-finger: g→h + misspelling: insertion)
- `gοoglе.com` (mixed-encodings: o→ο, e→е)

## Usage Examples

### Single Transformation
```bash
# Generate 1337speak variations only
./domfuzz -t 1337speak google.com

# Generate mixed-encoding (homograph) attacks only  
./domfuzz -t mixed-encodings google.com

# Generate fat-finger typing errors only
./domfuzz -t fat-finger google.com
```

### Multiple Transformations
```bash
# Use specific transformations
./domfuzz -t 1337speak,misspelling google.com

# Use default lookalike bundle (recommended)
./domfuzz google.com

# Use combo mode for advanced combinations
./domfuzz --combo google.com
```

### Advanced Options
```bash
# Limit output to top 50 variations
./domfuzz -n 50 google.com

# Check DNS resolution status  
./domfuzz -r google.com

# Output in JSON format
./domfuzz -j google.com

# Use custom TLD
./domfuzz -T .org google.com
```

## Security Considerations

### Defensive Applications
- **Brand Protection**: Monitor for typosquatting domains targeting your brand
- **Threat Intelligence**: Identify potential phishing domains before they're registered
- **Security Awareness**: Train users to recognize typosquatting attempts
- **DNS Monitoring**: Set up alerts for variations of critical domains

### Research Applications  
- **Academic Research**: Study typosquatting patterns and effectiveness
- **Security Testing**: Test organization's susceptibility to typosquatting
- **Algorithm Development**: Develop better detection mechanisms
- **Risk Assessment**: Evaluate brand vulnerability to domain confusion

### Ethical Guidelines
This tool is designed for defensive security research and brand protection. Users should:

- Only test domains they own or have permission to research
- Use results for defensive purposes (protection, monitoring, awareness)
- Respect applicable laws and regulations regarding domain research
- Avoid bulk registration of typosquatting domains for malicious purposes
- Report discovered malicious domains to appropriate authorities

## Algorithm Performance

### Similarity Scoring
DomFuzz uses Levenshtein distance-based similarity scoring:
- **90%+**: Very high similarity (most dangerous)
- **80-89%**: High similarity (significant risk)  
- **70-79%**: Moderate similarity (medium risk)
- **60-69%**: Lower similarity (still detectable by users)

### Output Prioritization
Results are automatically sorted by:
1. **Similarity score** (highest first)
2. **Transformation type** (grouped by method)
3. **Alphabetical order** (for consistent results)

This ensures the most dangerous variations appear first in the output.