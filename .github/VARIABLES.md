# Repository Variables

This document describes the recommended repository variables for this project.

## Required Variables

### Build Variables
- **BUILD_TYPE**: `Release` (for production builds)
- **CMAKE_BUILD_TYPE**: `Release`
- **MAX_PARALLEL_JOBS**: `4`

### Test Variables
- **TEST_TIMEOUT**: `300` (seconds)
- **INTEGRATION_TEST_TIMEOUT**: `600` (seconds)
- **COVERAGE_THRESHOLD**: `80` (percentage)

### Docker Variables
- **DOCKER_REGISTRY**: `docker.io`
- **DOCKER_IMAGE_NAME**: `rfc7030-est-client`
- **DOCKER_TAG_PREFIX**: `v`

## Optional Variables

### Documentation Variables
- **DOCS_BRANCH**: `gh-pages`
- **DOCS_DIR**: `docs/`
- **DOCS_BUILD_DIR**: `_build/`

### Release Variables
- **RELEASE_BRANCH**: `main`
- **RELEASE_TAG_PREFIX**: `v`
- **RELEASE_NOTES_TEMPLATE**: `.github/RELEASE_TEMPLATE.md`

### Notification Variables
- **NOTIFICATION_CHANNEL**: `#releases`
- **NOTIFICATION_USERNAME**: `GitHub Actions`

## Setup Instructions

1. Go to Settings > Secrets and variables > Actions
2. Click "Variables" tab
3. Click "New repository variable"
4. Enter the variable name and value
5. Click "Add variable"
6. Repeat for all required variables

## Usage in Workflows

Access variables in workflows using:

```yaml
env:
  BUILD_TYPE: ${{ vars.BUILD_TYPE }}
  TEST_TIMEOUT: ${{ vars.TEST_TIMEOUT }}
  MAX_PARALLEL_JOBS: ${{ vars.MAX_PARALLEL_JOBS }}
```

## Environment-Specific Variables

Use different variables for different environments:

- **Development**: `DEV_*`
- **Staging**: `STAGING_*`
- **Production**: `PROD_*`

## Variable Naming Convention

Use uppercase with underscores:
- `BUILD_TYPE`
- `TEST_TIMEOUT`
- `MAX_PARALLEL_JOBS`

## Access Control

- Limit variable access to specific workflows
- Use organization variables for shared resources
- Regularly audit variable access
- Remove unused variables
