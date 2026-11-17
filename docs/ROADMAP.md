# Product roadmap

## Delivered: 0.3

Bounded batch reviews, exact URL approval, configuration evidence, private standalone HTML reports, JSON v2, offline preview, package entry point automated test configuration, stable finding IDs and conservative offline report comparison.

## Next: stronger evidence

- Certificate expiry and negotiated TLS metadata with separate evidence and tests.
- Explicitly approved GET checks for servers that reject HEAD, with response size limits.
- Better policy parsing and context to reduce misleading findings.

## Then: AI-assisted interpretation

Provide explanations and remediation plans for already collected findings. Treat target-controlled evidence as untrusted input. Keep any AI provider credential in environment configuration; do not commit it. Show what report data will be sent and require explicit operator opt-in. AI suggestions must remain separate from observed evidence and never claim verified exploitability without verification. No model-controlled expansion of approved scope.

## Then: dashboard

Local project workspace, scan history, report comparison and findings review. Add authentication and tenant isolation before considering a hosted version. A static HTML report is the current review interface; it is not a live dashboard.

## Release criteria

Tests covering request boundaries and failure paths; verified packaging; documented data handling; reproducible local practice workflow. More checks are useful only when the evidence and limitations remain clear.
