# DomFuzz Project Overview

## Purpose
DomFuzz is a Rust CLI tool for generating domain name variations using various typosquatting techniques. It's designed for security research and defensive purposes to identify potential typosquatted domains.

## Tech Stack
- **Language**: Rust (Edition 2021)
- **CLI Framework**: clap v4.0 with derive feature
- **Async Runtime**: tokio v1.0 with full features
- **HTTP Client**: reqwest v0.12 with json features
- **DNS Resolution**: trust-dns-resolver v0.23
- **URL Parsing**: url v2.4

## Project Structure
- `src/main.rs` - Main CLI application with all typosquatting logic
- `Cargo.toml` - Project configuration and dependencies
- `README.md` - Comprehensive documentation with examples
- `LICENSE` - MIT license
- `target/` - Compiled binaries and build artifacts

## Key Features
The tool supports multiple typosquatting attack categories:
- Character-level attacks (substitution, homoglyphs, IDN homograph)
- Input-based attacks (keyboard proximity, misspellings)
- Domain structure attacks (TLD variations, subdomain injection)
- Brand confusion attacks (combosquatting, brand confusion)
- Technical attacks (bitsquatting)

## Binary Targets
- Main binary: `domfuzz` (path: src/main.rs)