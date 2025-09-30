# Repository Rules

This document describes the recommended repository rules for this project.

## Required Rules

### Branch Protection
- Require pull request reviews before merging
- Require status checks to pass before merging
- Require branches to be up to date before merging
- Restrict pushes that create files larger than 100MB

### Commit Message Format
- Use conventional commit format
- Include issue number in commit message
- Use descriptive commit messages

### Pull Request Requirements
- Require pull request template
- Require linked issues
- Require passing CI checks
- Require code review

## Optional Rules

### File Size Limits
- Maximum file size: 100MB
- Maximum repository size: 1GB
- Maximum number of files: 100,000

### Content Restrictions
- No binary files in source code
- No sensitive data in commits
- No large generated files

### Code Quality
- Require passing linting checks
- Require passing unit tests
- Require passing integration tests
- Require code coverage threshold

## Setup Instructions

1. Go to Settings > Rules
2. Click "Add rule"
3. Configure the rule settings
4. Save the rule
5. Test the rule

## Rule Categories

### Branch Rules
- Branch protection rules
- Branch naming conventions
- Branch deletion rules

### Commit Rules
- Commit message format
- Commit author requirements
- Commit signing requirements

### Pull Request Rules
- Pull request requirements
- Pull request templates
- Pull request review requirements

### File Rules
- File size limits
- File type restrictions
- File naming conventions

## Enforcement

### Automatic Enforcement
- GitHub automatically enforces most rules
- Some rules require manual review
- Use branch protection for critical rules

### Manual Enforcement
- Regular code reviews
- Manual rule checking
- Team training and education

## Custom Rules

### Custom Status Checks
- Create custom status checks
- Use external tools for validation
- Integrate with CI/CD pipeline

### Custom Review Requirements
- Require specific reviewers
- Require team approval
- Require external approval

## Best Practices

- Start with basic rules
- Gradually add more rules
- Test rules before enforcement
- Document rule changes
- Regularly review and update rules
