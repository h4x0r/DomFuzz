# Task Completion Checklist for DomFuzz

When completing any development task, run these commands:

1. **Code Quality Checks**
   - `cargo clippy` - Check for common mistakes and improvements
   - `cargo fmt` - Format code according to Rust standards
   - `cargo check` - Verify code compiles without errors

2. **Testing**
   - `cargo test` - Run all tests to ensure functionality works

3. **Build Verification**
   - `cargo build --release` - Ensure release build succeeds
   - Test the built binary with sample domains

4. **Documentation Updates**
   - Update README.md if functionality changes
   - Update Cargo.toml version if necessary
   - Update examples if CLI interface changes

5. **Before Publishing to Crates.io**
   - `cargo package` - Create and verify package contents
   - `cargo publish --dry-run` - Test publication process
   - `cargo publish` - Actual publication (only when ready)