# CLAUDE.md

## Project Configuration

### Permissions
- Default read/write access for authenticated users
- Admin access restricted to specific roles

### Hooks
- Pre-commit: Run static analysis, code formatting, and test execution
- Post-deploy: Sync configuration files and update security policies

### Security
- Use HTTPS for all API endpoints
- Regular security audits recommended
- Mandatory encryption for all sensitive data at rest and in transit

## Project Overview

This Java keystore project provides **tools for cryptographic operations, certificate management, and secure key storage**. Its primary functions include:

1. **Keystore Management**:
   - Generate and manage Java keystores (JKS/PKCS#12) with password-protected storage
   - Automate keystore creation using the `create_keys.sh` script

2. **Certificate Authority (CA) Operations**:
   - Generate root CA certificates and sign client certificates
   - Validate certificate chains using `keytool` and check expiry dates

3. **Secure Key Handling**:
   - Support for AES-256 encryption of sensitive data at rest
   - Integration with OpenSSL for advanced cryptographic operations

4. **Development & Security**:
   - Built with Java 17 and Maven, with dependencies on Log4j 2, JUnit 5, and Jacoco for testing
   - Enforces TLS 1.3 for secure communications
   - Pre-commit hooks enforce security checks and code quality standards
   - SonarCloud integration for code quality analysis

## Architecture

### Core Components
1. **Keystore Management**:
   - Java KeyStore (JKS) implementation
   - PKCS#12 format support
   - Secure key storage with password protection

2. **Certificate Authority (CA)**:
   - Root CA certificate generation
   - Client certificate signing
   - Certificate chain validation

3. **Security Utilities**:
   - OpenSSL integration for certificate operations
   - Cryptographic key generation
   - Secure random number generation

### Technology Stack
- Java 17 with Maven build system
- Log4j 2 for logging
- JUnit 5 for unit testing
- Jacoco for code coverage
- SonarCloud for code quality analysis

## Key Files

1. **create_keys.sh**:
   - Generates root CA certificate
   - Creates client certificate with root CA signing
   - Imports certificates into Java keystores (JKS format)
   - Validates keystore contents

2. **pom.xml**:
   - Maven build configuration
   - Dependency management (logging, testing, security utilities)
   - Integration with SonarCloud for code quality analysis
   - Code coverage configuration with Jacoco

3. **README.md**:
   - Installation instructions
   - Usage documentation
   - Configuration guidelines
   - Security best practices

## Security Implementation

1. **Encryption**:
   - AES-256 for keystore encryption
   - SHA-256 for certificate signing
   - Secure random number generation using Java's SecureRandom

2. **Access Control**:
   - Role-based access to keystore operations
   - Password-protected key storage
   - Audit logging for all access events

3. **Certificate Management**:
   - Valid certificate chain validation
   - Expiry date checking
   - Revocation list support

4. **Secure Practices**:
   - TLS 1.3 for secure communications
   - Regular security audits
   - Protection against common vulnerabilities (OWASP Top 10)

## Development Workflow

1. **Code Quality**:
   - Automated static analysis with SonarCloud
   - Code formatting with Spotless
   - Unit tests with JUnit 5
   - Code coverage with Jacoco

2. **Build Process**:
   - Maven-based build system
   - Automated testing with Surefire plugin
   - Code coverage reporting
   - Package output to target/output.zip

3. **Continuous Integration**:
   - GitHub Actions for CI/CD
   - Automated testing and quality checks
   - Security scan integration