# GitHub Repository Setup Guide

This guide will help you set up the GitHub repository with all the recommended configurations.

## Prerequisites

- GitHub account with repository creation permissions
- Repository already created
- Admin access to the repository

## Step-by-Step Setup

### 1. Basic Repository Settings

1. Go to **Settings** > **General**
2. Configure repository name and description
3. Add topics: `est`, `rfc7030`, `tls`, `x509`, `certificates`, `enrollment`, `c`, `cmake`, `openssl`
4. Enable features:
   - ✅ Issues
   - ✅ Projects
   - ❌ Wiki
   - ✅ Discussions
   - ✅ Sponsors
   - ✅ Pages

### 2. Security Settings

1. Go to **Settings** > **Security**
2. Enable all security features:
   - ✅ Vulnerability alerts
   - ✅ Dependabot alerts
   - ✅ Dependabot security updates
   - ✅ Secret scanning
   - ✅ Push protection
   - ✅ Code scanning
   - ✅ Dependency graph

### 3. Access Control

1. Go to **Settings** > **Branches**
2. Add branch protection rule for `main`:
   - Require pull request reviews
   - Require status checks
   - Require up-to-date branches
   - Restrict push access
   - Require conversation resolution

2. Go to **Settings** > **Collaborators and teams**
3. Add collaborators with appropriate permissions
4. Set up teams if needed

### 4. GitHub Actions

1. Go to **Settings** > **Actions** > **General**
2. Configure:
   - ✅ Allow all actions and reusable workflows
   - ✅ Allow actions created by GitHub
   - ✅ Allow actions by Marketplace verified creators

### 5. Packages

1. Go to **Settings** > **Packages**
2. Enable:
   - ✅ GitHub Packages
   - ✅ Docker support

### 6. Pages

1. Go to **Settings** > **Pages**
2. Configure:
   - Source: Deploy from a branch
   - Branch: `gh-pages`
   - ✅ Enable HTTPS

### 7. Notifications

1. Go to **Settings** > **Notifications**
2. Configure email preferences
3. Set up web notifications
4. Configure mobile notifications

### 8. Environments

1. Go to **Settings** > **Environments**
2. Create environments:
   - `development`
   - `staging`
   - `production`
3. Configure protection rules for each

### 9. Secrets and Variables

1. Go to **Settings** > **Secrets and variables** > **Actions**
2. Add required secrets (see [SECRETS.md](./SECRETS.md))
3. Add required variables (see [VARIABLES.md](./VARIABLES.md))

### 10. Webhooks

1. Go to **Settings** > **Webhooks**
2. Add required webhooks (see [WEBHOOKS.md](./WEBHOOKS.md))

### 11. Rules

1. Go to **Settings** > **Rules**
2. Add repository rules (see [RULES.md](./RULES.md))

### 12. Insights

1. Go to **Insights** tab
2. Explore available insights
3. Set up custom dashboards

## Verification

### Test CI/CD Pipeline
1. Push a commit to trigger CI
2. Verify all workflows run successfully
3. Check status badges in README

### Test Security Features
1. Create a test issue
2. Verify security scanning works
3. Check Dependabot alerts

### Test Access Control
1. Try to push directly to main branch
2. Verify branch protection works
3. Test pull request process

### Test Notifications
1. Create a test issue
2. Verify notifications are sent
3. Check notification settings

## Troubleshooting

### Common Issues
- **Workflows not running**: Check Actions permissions
- **Security scans failing**: Check security settings
- **Notifications not working**: Check notification settings
- **Access denied**: Check permission settings

### Getting Help
- Check GitHub documentation
- Open an issue in the repository
- Contact repository maintainers

## Maintenance

### Regular Tasks
- Review security alerts
- Update dependencies
- Monitor repository activity
- Review and update settings

### Monthly Tasks
- Review contributor permissions
- Update documentation
- Check webhook configurations
- Review notification settings

### Quarterly Tasks
- Review repository rules
- Update security settings
- Review access control
- Plan improvements

## Best Practices

- Start with basic settings
- Gradually add advanced features
- Test configurations thoroughly
- Document all changes
- Regularly review and update
- Share knowledge with team
