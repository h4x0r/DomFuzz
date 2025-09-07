#!/bin/bash

# Script to update GitHub Action SHA pins using pin-github-action
# This ensures all actions are pinned to their latest SHA hashes for security

echo "🔐 Updating GitHub Action SHA pins..."

# Check if pin-github-action is installed
if ! command -v pin-github-action &> /dev/null; then
    echo "❌ pin-github-action not found. Installing..."
    npm install -g pin-github-action
fi

# Update all workflow files
echo "📝 Processing workflow files..."
for workflow in .github/workflows/*.yml; do
    if [ -f "$workflow" ]; then
        echo "  Processing: $workflow"
        pin-github-action "$workflow"
    fi
done

echo "✅ All GitHub Action SHA pins updated!"
echo ""
echo "🔍 Verifying pins..."
# Check if any workflow files contain version tags instead of SHA hashes
if grep -r '@v[0-9]' .github/workflows/ >/dev/null 2>&1 || \
   grep -r '@[0-9]\+\.[0-9]\+' .github/workflows/ >/dev/null 2>&1; then
    echo "❌ Verification failed - some actions still use version tags:"
    echo "   Version tags found:"
    grep -r '@v[0-9]' .github/workflows/ 2>/dev/null || true
    grep -r '@[0-9]\+\.[0-9]\+' .github/workflows/ 2>/dev/null || true
    echo "   Run the script again to fix remaining issues"
    exit 1
else
    echo "✅ All actions are properly pinned to SHA hashes"
fi

echo ""
echo "🎯 Next steps:"
echo "1. Review the changes with: git diff"
echo "2. Commit the updates: git add . && git commit -m 'Update GitHub Action SHA pins'"
echo "3. Push to trigger CI validation: git push"
