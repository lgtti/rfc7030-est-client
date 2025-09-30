# Branch Protection Rules

This document describes the recommended branch protection rules for this repository.

## Main Branch Protection

### Required Status Checks
- CI/CD Pipeline
- Integration Tests Only
- Multi-Platform Build
- CodeQL Analysis

### Required Reviews
- At least 1 reviewer
- Dismiss stale reviews when new commits are pushed
- Require review from code owners

### Additional Rules
- Require branches to be up to date before merging
- Require conversation resolution before merging
- Restrict pushes that create files larger than 100MB
- Allow force pushes (disabled)
- Allow deletions (disabled)

## Development Branch Protection

### Required Status Checks
- CI/CD Pipeline
- Multi-Platform Build

### Required Reviews
- At least 1 reviewer

### Additional Rules
- Require branches to be up to date before merging
- Require conversation resolution before merging

## Setup Instructions

1. Go to Settings > Branches
2. Add rule for `main` branch
3. Configure the settings as described above
4. Add rule for `develop` branch (if using)
5. Configure with development-specific settings

## Code Owners

Create a `.github/CODEOWNERS` file to automatically request reviews from specific users or teams.

Example:
```
# Global owners
* @lorenzo

# Backend implementations
src/openssl/ @lorenzo
src/*/ @lorenzo

# Documentation
*.md @lorenzo
.github/ @lorenzo
```
