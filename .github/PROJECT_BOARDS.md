# Project Boards

This document describes the recommended project boards for this repository.

## Development Board

### Columns
1. **Backlog** - Ideas and future work
2. **To Do** - Ready to be worked on
3. **In Progress** - Currently being worked on
4. **Review** - Ready for review
5. **Done** - Completed work

### Automation
- Move issues to "In Progress" when assigned
- Move PRs to "Review" when opened
- Move to "Done" when merged

## Release Board

### Columns
1. **Planning** - Features planned for next release
2. **Development** - Features being developed
3. **Testing** - Features being tested
4. **Release** - Features ready for release
5. **Released** - Features in current release

### Automation
- Move issues to "Development" when assigned
- Move to "Testing" when PR is opened
- Move to "Release" when PR is merged
- Move to "Released" when milestone is closed

## Setup Instructions

1. Go to Projects tab
2. Create new project
3. Choose "Board" layout
4. Configure columns as described above
5. Set up automation rules
6. Add issues and PRs to the board

## Labels Integration

Use the following labels to automatically categorize work:
- `bug` - Bug fixes
- `enhancement` - New features
- `documentation` - Documentation updates
- `backend` - Backend implementations
- `integration-tests` - Testing related
- `security` - Security related
- `good first issue` - Good for newcomers
- `help wanted` - Needs community help
