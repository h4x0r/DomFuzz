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
if pin-github-action --check .github/workflows/*.yml; then
    echo "✅ All actions are properly pinned to SHA hashes"
else
    echo "❌ Verification failed - some actions may not be properly pinned"
    exit 1
fi

echo ""
echo "🎯 Next steps:"
echo "1. Review the changes with: git diff"
echo "2. Commit the updates: git add . && git commit -m 'Update GitHub Action SHA pins'"
echo "3. Push to trigger CI validation: git push"