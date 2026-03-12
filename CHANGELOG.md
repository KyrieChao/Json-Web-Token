# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.1-SNAPSHOT] - 2026-03-12

### Added
- **Core**: Initial release of KeyMinter core logic.
- **Algorithms**: Support for HMAC (HS256/384/512), RSA (RS256/384/512), ECDSA (ES256/384/512), EdDSA (Ed25519/Ed448).
- **Key Rotation**: Automated key rotation with configurable validity and transition periods.
- **Storage**: FileSystem-based key repository implementation.
- **Locking**: Local and Redis-based distributed locking support.
- **Spring Boot**: Auto-configuration and `KeyMinterProperties` integration.
- **Testing**: Comprehensive unit tests with JUnit 5 and Jacoco coverage reports.
- **Documentation**: Initial README with usage examples and architecture overview.

### Changed
- Refactored `AbstractJwtAlgo` to support strategy pattern for different algorithms.
- Improved error handling for key loading and migration.

### Fixed
- Legacy key migration issues for HMAC and ECDSA.
- Null pointer exceptions in `DomainModel` edge cases.
