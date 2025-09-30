# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability, please follow these steps:

1. **Do not** create a public GitHub issue
2. Email us directly at: [security@yourdomain.com]
3. Include the following information:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Response Timeline

- We will acknowledge receipt within 48 hours
- We will provide a detailed response within 7 days
- We will keep you informed of our progress

## Security Considerations

This EST client handles:
- TLS/SSL connections
- X.509 certificate validation
- Cryptographic operations
- Network communications

Please ensure any security reports include:
- Environment details (OS, compiler, OpenSSL version)
- Network configuration
- Certificate details (sanitized)
- Error logs

## Security Best Practices

When using this EST client:
- Always validate server certificates
- Use strong authentication methods
- Keep dependencies updated
- Monitor for security advisories
- Use HTTPS/TLS in production environments
