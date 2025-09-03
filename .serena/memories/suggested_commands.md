# Suggested Commands for DomFuzz Development

## Build Commands
- `cargo build` - Build debug version
- `cargo build --release` - Build optimized release version
- `cargo check` - Check code without building

## Testing Commands
- `cargo test` - Run all tests
- `cargo test --release` - Run tests in release mode

## Code Quality Commands
- `cargo clippy` - Run Rust linter
- `cargo fmt` - Format code according to Rust style
- `cargo clippy -- -D warnings` - Run clippy with warnings as errors

## Running the Application
- `./target/debug/domfuzz <domain>` - Run debug version
- `./target/release/domfuzz <domain>` - Run release version
- `cargo run -- <domain>` - Build and run with cargo

## Package Management
- `cargo publish` - Publish to crates.io
- `cargo package` - Create package for distribution
- `cargo update` - Update dependencies

## Development Utilities
- `ls -la` - List files (macOS/Darwin)
- `find . -name "*.rs"` - Find Rust source files
- `grep -r "pattern" src/` - Search for patterns in source