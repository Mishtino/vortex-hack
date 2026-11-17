# Changelog

## 0.2.0

- Batch checks against up to 20 exact approved URLs, with sequential requests and a one-second pause.
- Standalone HTML reporting with escaped content, CSP, responsive layout and print styles.
- JSON schema v2 with per-target outcomes, summary counts and connection errors.
- HTML-aware checks, invalid nosniff detection and basic HSTS max-age validation.
- Stricter scope, URL and timeout validation; existing report files are protected.
- Offline demonstration mode, optional package installation and severity exit thresholds.
- Local integration tests and a GitHub Actions Python matrix.

## 0.1.0

- Initial single-URL HEAD scanner with scope approval, configuration observations and JSON output.
