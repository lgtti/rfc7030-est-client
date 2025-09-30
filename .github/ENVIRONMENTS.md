# Repository Environments

This document describes the recommended repository environments for this project.

## Required Environments

### Development
- **Name**: `development`
- **Protection Rules**: None
- **Secrets**: Development-specific secrets
- **Variables**: Development-specific variables

### Staging
- **Name**: `staging`
- **Protection Rules**: Require review
- **Secrets**: Staging-specific secrets
- **Variables**: Staging-specific variables

### Production
- **Name**: `production`
- **Protection Rules**: Require review, restrict to main branch
- **Secrets**: Production-specific secrets
- **Variables**: Production-specific variables

## Optional Environments

### Testing
- **Name**: `testing`
- **Protection Rules**: None
- **Secrets**: Testing-specific secrets
- **Variables**: Testing-specific variables

### Documentation
- **Name**: `documentation`
- **Protection Rules**: Require review
- **Secrets**: Documentation-specific secrets
- **Variables**: Documentation-specific variables

## Setup Instructions

1. Go to Settings > Environments
2. Click "New environment"
3. Enter the environment name
4. Configure protection rules
5. Add environment-specific secrets
6. Add environment-specific variables
7. Save the environment

## Protection Rules

### Required Reviewers
- Add specific users or teams as reviewers
- Require approval from at least 1 reviewer
- Dismiss stale reviews when new commits are pushed

### Wait Timer
- Set a wait time before deployment
- Useful for production deployments

### Deployment Branches
- Restrict deployments to specific branches
- Use patterns like `main` or `release/*`

## Environment-Specific Configuration

### Development
```yaml
env:
  BUILD_TYPE: Debug
  TEST_TIMEOUT: 60
  MAX_PARALLEL_JOBS: 2
```

### Staging
```yaml
env:
  BUILD_TYPE: RelWithDebInfo
  TEST_TIMEOUT: 300
  MAX_PARALLEL_JOBS: 4
```

### Production
```yaml
env:
  BUILD_TYPE: Release
  TEST_TIMEOUT: 600
  MAX_PARALLEL_JOBS: 8
```

## Usage in Workflows

Reference environments in workflows:

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Deploy
        run: echo "Deploying to production"
```

## Best Practices

- Use environments for different deployment stages
- Apply appropriate protection rules
- Use environment-specific secrets
- Monitor environment usage
- Regularly audit environment access
