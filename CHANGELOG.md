# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Upgrade things-go/go-socks5 to v0.0.6.
- Move proxy logic into its own internal package.
- Handle logging with the UserConnectionMiddleware.

## [0.1.1] - 2025-04-02

### Fixed

- Fix service selector in the Helm chart.

## [0.1.0] - 2025-04-01

### Added

- Initial release of the app.
- Add support for credentials

[Unreleased]: https://github.com/giantswarm/proxysocks/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/giantswarm/proxysocks/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/giantswarm/proxysocks/releases/tag/v0.1.0
