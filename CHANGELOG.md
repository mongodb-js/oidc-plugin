# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2025-08-05

### Added

- First-class support for user-supplied token cache via `tokenCache` option
- New `OidcToken` and `TokenCache` interfaces for external token persistence
- Automatic cache consultation before interactive authentication flows
- Cache population after successful token acquisition
- Token sharing between parallel Jest workers and Node.js processes

### Changed

- Enhanced `MongoDBOIDCPluginOptions` interface with optional `tokenCache` property

## [2.0.1] - Previous Release

- See git history for previous changes
