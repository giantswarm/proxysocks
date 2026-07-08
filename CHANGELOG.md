# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Metrics: `proxysocks_auth_failures_total`, `proxysocks_active_connections`, and `proxysocks_connection_errors_total`.
- Chart: a ServiceMonitor and a ClusterIP metrics Service to scrape `/metrics` (toggle via `metrics.serviceMonitor.enabled`).
- Configurable listen addresses via `--socks-address` and `--metrics-address` flags.
- Graceful shutdown: on SIGTERM, stop accepting, drain in-flight connections, then stop the metrics server.

### Changed

- Probe the SOCKS5 port via `tcpSocket` for readiness and add a liveness probe.
- Log in JSON via `log/slog`.
- Fail startup with an error instead of `log.Fatalf` when authentication cannot be configured.
- Inject the version at build time via ldflags instead of hardcoding it.

### Removed

- Remove the always-ok `/healthz` endpoint.
- Remove the unused viper config machinery and cobra scaffolding (`--config`, `toggle` flag, placeholder descriptions).

## [0.3.0] - 2026-07-07

### Added

- Support multiple users via a Secret-mounted htpasswd credentials file (bcrypt hashes).
- Add `user` label to the `proxysocks_user_connect_total` metric.

### Changed

- Deliver credentials through a mounted htpasswd file instead of environment variables.

### Removed

- Drop the `PROXY_USERNAME`/`PROXY_PASSWORD` env var auth in favor of the htpasswd file.

## [0.2.1] - 2025-08-27

### Changed

- Use container image from gsoci.azurecr.io

## [0.2.0] - 2025-05-08

### Added
- Add health endpoint
- Add metrics endpoint
- Add proxysocks_user_connect_total metric

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

[Unreleased]: https://github.com/giantswarm/proxysocks/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/giantswarm/proxysocks/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/giantswarm/proxysocks/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/giantswarm/proxysocks/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/giantswarm/proxysocks/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/giantswarm/proxysocks/releases/tag/v0.1.0
