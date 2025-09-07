# GitHub Actions Security: Hybrid Dependabot + Pinact Approach

This repository implements a **hybrid security approach** for GitHub Actions that combines **automated updates** with **SHA pinning** for optimal security and maintenance.

## 🛡️ Security Model

### The Problem
- **Version tags** (`@v4.0.0`) can be manipulated by attackers
- **Automatic updates** without SHA pinning create supply chain risks  
- **Manual SHA management** is error-prone and time-consuming

### Our Solution: Hybrid Approach
1. **Dependabot** creates PRs for version updates (monthly)
2. **Auto-pin workflow** automatically converts versions to SHA hashes
3. **CI validation** ensures all actions stay pinned to SHA hashes

## 🔧 How It Works

### Dependabot Updates (.github/dependabot.yml)
```yaml
- package-ecosystem: "github-actions"
  schedule:
    interval: "monthly"        # Reduced frequency
  open-pull-requests-limit: 3  # Limited PRs
```

### Automatic SHA Pinning (.github/workflows/auto-pin-actions.yml)
- **Triggered by:** Workflow changes, monthly schedule, manual dispatch
- **Action:** Runs `pin-github-action` to convert all version tags to SHA hashes
- **Result:** Commits SHA-pinned actions back to main branch

### CI Validation (.github/workflows/ci.yml)
```yaml
verify-action-pins:
  # Validates all actions use SHA hashes
  # Fails CI if any unpinned actions are found
```

## 📋 Workflow Process

1. **Monthly**: Dependabot creates PR with version updates (`@v4.1.0`)
2. **On merge**: Auto-pin workflow detects changes and runs Pinact
3. **Auto-commit**: SHA-pinned versions (`@abc123...`) are committed
4. **CI validation**: Ensures all actions remain properly pinned

## 🎯 Benefits

### Security
- ✅ **Tamper-proof** - SHA hashes cannot be manipulated
- ✅ **Supply chain protection** - Prevents tag-based attacks
- ✅ **Audit trail** - Exact commit versions documented

### Automation  
- ✅ **Auto-updates** - Dependabot handles version discovery
- ✅ **Auto-pinning** - No manual SHA hash management
- ✅ **CI enforcement** - Automatic validation prevents mistakes

### Maintenance
- ✅ **Reduced frequency** - Monthly instead of weekly updates
- ✅ **Error prevention** - No more manual SHA hash lookup failures
- ✅ **Self-healing** - Auto-pin workflow fixes unpinned actions

## 🛠️ Manual Operations

### Force Update All Actions
```bash
# Run the update script
./scripts/update-action-pins.sh

# Or trigger the workflow manually
gh workflow run auto-pin-actions.yml
```

### Check Pinning Status
```bash
# Verify all actions are pinned
pin-github-action --check .github/workflows/*.yml

# Pin any unpinned actions
pin-github-action .github/workflows/*.yml
```

### Emergency SHA Update
If a specific action needs immediate updating:
```bash
# Find the latest SHA for an action
gh api repos/actions/checkout/commits/main --jq '.sha'

# Manually update in workflow file
# Then commit changes - auto-pin will validate
```

## 📊 Configuration Summary

| Component | Purpose | Frequency | Automation |
|-----------|---------|-----------|------------|
| Dependabot | Version discovery | Monthly | Full |
| Auto-pin workflow | SHA conversion | On changes + Monthly | Full |  
| CI validation | SHA enforcement | Every commit | Full |
| Manual script | Emergency updates | As needed | Helper |

## 🔍 Monitoring

The auto-pin workflow provides detailed summaries:
- ✅ Actions successfully pinned
- ⚠️ Actions that couldn't be pinned  
- 📋 Security benefits documentation
- 🔗 Links to commit changes

## 🚨 Troubleshooting

### Action Not Found Error
```
Error: Unable to find SHA for action@version
```
**Solution:** The version tag doesn't exist. Check available tags:
```bash
gh api repos/owner/action/tags --jq '.[].name'
```

### CI Validation Failing
```  
❌ Some actions are not pinned to SHA hashes
```
**Solution:** Run auto-pin manually:
```bash
gh workflow run auto-pin-actions.yml
```

### Dependabot PR Issues
If Dependabot creates conflicting PRs, the auto-pin workflow will:
1. Detect the workflow changes
2. Automatically pin the new versions  
3. Commit the SHA-pinned updates
4. Close the loop with CI validation

This hybrid approach provides **maximum security with minimum maintenance overhead**.