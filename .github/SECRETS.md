# Repository Secrets

This document describes the recommended repository secrets for this project.

## Required Secrets

### CI/CD Secrets
- **SECRET_KEY**: Secret key for signing releases
- **DOCKER_USERNAME**: Docker Hub username for publishing images
- **DOCKER_PASSWORD**: Docker Hub password/token

### Security Secrets
- **CODECOV_TOKEN**: Codecov token for coverage reporting
- **SONAR_TOKEN**: SonarCloud token for code analysis

### Notification Secrets
- **SLACK_WEBHOOK**: Slack webhook URL for notifications
- **DISCORD_WEBHOOK**: Discord webhook URL for notifications

## Optional Secrets

### Documentation Secrets
- **DOCS_DEPLOY_KEY**: SSH key for deploying documentation
- **DOCS_DEPLOY_TOKEN**: Token for documentation deployment

### Testing Secrets
- **TEST_SERVER_URL**: URL for external test server
- **TEST_SERVER_TOKEN**: Token for external test server

### Release Secrets
- **GITHUB_TOKEN**: GitHub token for releases (usually auto-provided)
- **NPM_TOKEN**: NPM token for publishing packages

## Setup Instructions

1. Go to Settings > Secrets and variables > Actions
2. Click "New repository secret"
3. Enter the secret name and value
4. Click "Add secret"
5. Repeat for all required secrets

## Security Best Practices

- Never commit secrets to the repository
- Use repository secrets for sensitive data
- Rotate secrets regularly
- Use least privilege principle
- Monitor secret usage
- Use environment-specific secrets

## Environment Variables

For non-sensitive configuration, use environment variables in workflows:

```yaml
env:
  BUILD_TYPE: Release
  TEST_TIMEOUT: 300
  MAX_PARALLEL_JOBS: 4
```

## Secret Naming Convention

Use uppercase with underscores:
- `DOCKER_USERNAME`
- `SLACK_WEBHOOK`
- `CODECOV_TOKEN`

## Access Control

- Limit secret access to specific workflows
- Use organization secrets for shared resources
- Regularly audit secret access
- Remove unused secrets
