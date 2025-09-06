# Changelog

All notable changes to DomFuzz will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Fixed RUSTSEC-2024-0421: Updated `idna` dependency from vulnerable 0.4.0 to secure 1.1.0
- Fixed RUSTSEC-2025-0017: Migrated from deprecated `trust-dns-resolver` to maintained `hickory-resolver` 0.24

### Added
- Comprehensive transformation documentation in `TRANSFORMATIONS.md`
- Detailed explanations and examples for all 22 transformation algorithms
- Security considerations and ethical guidelines
- Performance characteristics documentation

### Changed
- Migrated DNS resolution from `trust-dns-resolver` to `hickory-resolver` for long-term maintenance
- Improved code quality by fixing all clippy linting warnings
- Enhanced documentation structure with dedicated transformation guide

### Fixed
- All clippy linting warnings resolved while preserving functionality
- Security vulnerabilities in dependency chain addressed
- Maintained backward compatibility during dependency migration

## [0.1.3] - 2024-12-XX

### Breaking Changes
- **Consolidated overlapping transformations** for cleaner architecture:
  - Merged `omission`, `addition`, `double-char-replacement`, `keyboard`, and `vowel-swap` into `misspelling`
  - Merged `homoglyphs`, `idn-homograph`, `mixed-script`, `extended-unicode`, and `cyrillic-comprehensive` into `mixed-encodings`
- **Changed default mode** from combo mode to single transformation mode (`-1`)

### Added
- **Transformation source information** in output format: `score, domain, transformation_name`
- Better organization with reduced code duplication

### Changed
- **Reduced transformation count** from 30+ to 22 core transformations
- **Improved architecture** with cleaner transformation groupings

### Improved
- Enhanced code organization and maintainability
- More intuitive transformation naming and grouping

## [0.1.2] - 2024-11-XX

### Added
- **New `lookalike` transformation bundle** for comprehensive visual similarity attacks
  - Includes core character-level transformations: `1337speak`, `misspelling`, `fat-finger`, `mixed-encodings`
- **True streaming architecture** with configurable batch sizes for better performance
- **Progress bars** for concurrent domain status checking operations
- **System-fault bundle** for hardware error simulations (`bitsquatting`)

### Breaking Changes
- **Changed default behavior** from `all` transformations to `lookalike` bundle for more practical defaults

### Improved
- **Modified Unicode/script transformations** to use position-based substitutions
- **Optimized `mixed-encodings`** to generate more comprehensive variations
- Enhanced performance with better memory management

### Performance
- Significantly improved streaming performance for large domain sets
- Better memory efficiency with HashSet deduplication
- Concurrent network operations with configurable parallelism

## [0.1.1] - 2024-10-XX

### Added
- **13 new fuzzing transformations** sourced from URLCrazy, dnstwist, URLInsane, and DomainFuzz
- **Organized transformations into logical groups**:
  - Character-level (1337speak, misspelling, fat-finger, mixed-encodings, bitsquatting)
  - Phonetic/Semantic (homophones, cognitive, singular-plural)
  - Number/Word substitution (cardinal-substitution, ordinal-substitution)
  - Structure manipulation (word-swap, hyphenation, subdomain, dot operations)
  - Domain extensions (TLD variations, combosquatting, brand confusion)
- **Enhanced CLI interface** with transformation groupings in help text
- **Comprehensive Unicode support** with extensive homoglyph database
- **Detailed documentation** covering all transformation algorithms

### Improved
- Better command-line argument organization
- More intuitive transformation selection
- Enhanced help system with examples

### Performance
- Optimized character substitution algorithms
- Improved memory usage for large domain sets

## [0.1.0] - 2024-09-XX

### Added
- **Initial release** with core typosquatting functionality
- **Basic transformations**:
  - Leetspeak character substitutions
  - Common misspelling patterns
  - Fat-finger keyboard errors
  - Unicode homoglyph attacks
- **Domain status checking** with DNS resolution
- **Network availability testing** for generated variations
- **Configurable output limits** and filtering options
- **Dictionary-based combosquatting** support
- **High-performance Rust implementation** with async networking

### Features
- Command-line interface with comprehensive options
- Multiple output formats (plain text with optional status)
- Concurrent domain checking with timeout handling
- Memory-efficient domain generation and deduplication
- Cross-platform compatibility (Windows, macOS, Linux)

---

## Security Advisories

### RUSTSEC-2024-0421 (Fixed in unreleased)
**Impact**: idna crate accepts malformed Punycode labels  
**Severity**: Medium  
**Solution**: Updated to idna ≥1.0.0  
**Status**: ✅ Fixed

### RUSTSEC-2025-0017 (Fixed in unreleased)
**Impact**: trust-dns project deprecated  
**Severity**: Low (maintenance warning)  
**Solution**: Migrated to hickory-resolver  
**Status**: ✅ Fixed

---

## Development Notes

### Version Numbering
- **Major version** (x.0.0): Breaking API changes or significant architectural changes
- **Minor version** (0.x.0): New features, transformations, or non-breaking enhancements  
- **Patch version** (0.0.x): Bug fixes, security updates, and minor improvements

### Transformation Evolution
The transformation system has evolved significantly:
- **v0.1.0**: Basic transformations (4 core types)
- **v0.1.1**: Expanded to 30+ transformations from multiple sources
- **v0.1.2**: Introduced bundle system, optimized for practical usage
- **v0.1.3**: Consolidated to 22 core transformations, cleaner architecture
- **Current**: Enhanced security, documentation, and maintainability

### Migration Guide

#### From 0.1.2 to 0.1.3
- **Transformation names**: Some transformations merged into others
  - `keyboard` → use `misspelling` (includes keyboard errors)
  - `vowel-swap` → use `misspelling` (includes vowel variations)
  - `homoglyphs` → use `mixed-encodings` (includes all Unicode attacks)
- **Default mode**: Now single-transformation (`-1`) instead of combo
- **Output format**: Now includes transformation name in output

#### From 0.1.1 to 0.1.2  
- **Default behavior**: Changed from `all` to `lookalike` bundle
- **New bundles**: Use `-t lookalike` or `-t system-fault` for curated sets
- **Performance**: Streaming architecture may affect very large datasets