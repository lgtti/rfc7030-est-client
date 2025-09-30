# Contributing to RFC7030 EST Client

Thank you for your interest in contributing to the RFC7030 EST Client! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your changes
4. Make your changes
5. Test your changes thoroughly
6. Submit a pull request

## Development Setup

### Prerequisites
- CMake 3.10+
- C compiler (GCC, Clang, or MSVC)
- OpenSSL development libraries
- Git

### Building
```bash
# Clone with submodules
git clone --recursive https://github.com/your-username/rfc7030-est-client.git
cd rfc7030-est-client

# Configure and build
cmake -Ssrc -Bbuild -DUSE_OPENSSL=ON
cd build
make
```

### Testing
```bash
# Run unit tests
./bin/rfc7030-est-client-tests

# Run integration tests (requires Docker)
cd ../test
./run-integration-tests.sh
```

## Code Style

- Follow existing code style and conventions
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small

## Backend Development

If you're implementing a new TLS/X.509 backend:

1. Create a new directory in `src/` (e.g., `src/myssl/`)
2. Implement all required functions in `src/lib/include/rfc7030.h`
3. Create a CMake configuration file
4. Add build options to `src/CMakeLists.txt`
5. Update documentation
6. Add tests

See the existing OpenSSL implementation in `src/openssl/` for reference.

## Testing Requirements

- All unit tests must pass
- Integration tests must pass (if applicable)
- New functionality requires new tests
- Backend implementations require comprehensive testing

## Pull Request Process

1. Ensure all CI checks pass
2. Update documentation if needed
3. Add tests for new functionality
4. Follow the pull request template
5. Request review from maintainers

## Issue Reporting

When reporting bugs:
- Use the bug report template
- Include environment details
- Provide steps to reproduce
- Include relevant logs

For feature requests:
- Use the feature request template
- Describe the use case
- Consider implementation complexity

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

## Questions?

Feel free to open an issue for questions or discussions!
