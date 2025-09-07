#!/bin/bash

# Setup Git hooks for DomFuzz development
# Installs pre-push validation hooks to catch issues before they reach CI

echo "🎣 Setting up Git hooks for DomFuzz..."

# Create hooks directory if it doesn't exist
mkdir -p .git/hooks

# Check if pre-push hook already exists
if [ -f ".git/hooks/pre-push" ] && [ ! -L ".git/hooks/pre-push" ]; then
    echo "⚠️  Existing pre-push hook found"
    read -p "Replace existing hook? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Hook installation cancelled"
        exit 1
    fi
fi

# Copy the pre-push hook template
if [ -f "scripts/templates/pre-push" ]; then
    cp scripts/templates/pre-push .git/hooks/pre-push
elif [ -f ".git/hooks/pre-push" ]; then
    echo "✅ Pre-push hook already installed"
else
    echo "❌ Pre-push hook template not found"
    echo "   Expected: scripts/templates/pre-push"
    exit 1
fi

# Make it executable
chmod +x .git/hooks/pre-push

echo "✅ Pre-push hook installed successfully!"
echo
echo "📋 Hook validates before each push:"
echo "  • 🎨 Code formatting (cargo fmt)"
echo "  • 🔧 Linting (cargo clippy)"
echo "  • 🛡️  Security audit (cargo audit)"
echo "  • 🧪 Test suite (cargo test)"
echo "  • 🔨 Release build (cargo build --release)"
echo "  • 📌 GitHub Actions SHA pinning"
echo "  • 🔐 Sigstore commit signing (if configured)"
echo
echo "💡 To bypass hook in emergency: git push --no-verify"
echo "🛠️  To test hook: git push --dry-run"