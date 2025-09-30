# Repository Permissions

This document describes the recommended permission settings for this repository.

## Permission Levels

### Admin
- Full repository access
- Can manage all settings
- Can delete repository
- Can manage collaborators

### Maintain
- Can manage issues and PRs
- Can manage projects
- Can manage discussions
- Cannot delete repository

### Write
- Can push to repository
- Can create branches
- Can manage issues and PRs
- Cannot manage settings

### Triage
- Can manage issues and PRs
- Can manage discussions
- Cannot push to repository
- Cannot manage settings

### Read
- Can view repository
- Can clone repository
- Can create issues and PRs
- Cannot push to repository

## Recommended Permissions

### Repository Owner
- **Level**: Admin
- **Access**: Full access
- **Responsibilities**: Repository management

### Core Maintainers
- **Level**: Maintain
- **Access**: Issue/PR management
- **Responsibilities**: Code review, releases

### Contributors
- **Level**: Write
- **Access**: Push access
- **Responsibilities**: Code contributions

### Community Moderators
- **Level**: Triage
- **Access**: Issue/PR management
- **Responsibilities**: Community management

### Community Members
- **Level**: Read
- **Access**: View only
- **Responsibilities**: Community participation

## Setup Instructions

1. Go to Settings > Collaborators and teams
2. Add collaborators
3. Set permission levels
4. Configure team permissions
5. Test permissions

## Team Permissions

### Core Team
- **Permission**: Maintain
- **Members**: Core maintainers
- **Access**: Full repository access

### Contributors Team
- **Permission**: Write
- **Members**: Active contributors
- **Access**: Push access

### Community Team
- **Permission**: Triage
- **Members**: Community moderators
- **Access**: Issue/PR management

## Access Control

### Branch Protection
- Require pull request reviews
- Require status checks
- Restrict push access
- Require up-to-date branches

### Code Owners
- Automatic review requests
- Required reviewers
- Code ownership
- Review requirements

### Security Settings
- Vulnerability alerts
- Secret scanning
- Code scanning
- Dependency updates

## Best Practices

- Use least privilege principle
- Regularly review permissions
- Remove unused access
- Monitor access activity
- Use teams for group permissions
- Document permission changes
