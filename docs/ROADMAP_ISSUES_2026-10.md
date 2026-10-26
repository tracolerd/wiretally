# Prioritized Engineering Backlog

These candidate issues are grounded in the current documented PCAP/PCAPNG and local-first prototype scope. Verify each behavior against a reproducible input before classifying it as a confirmed bug.

## Candidate issues

1. **Add an automated Python test suite** — Cover capture validation, TShark parsing, bidirectional flow aggregation, rule evaluation, and JSON report output with small fixtures.
2. **Add reproducible CI checks** — Run formatting/linting, Python tests, and type checks in GitHub Actions; document any required TShark dependency.
3. **Bound TShark execution time and output size** — Apply a configurable timeout and safe failure handling for malformed or unusually large captures.
4. **Restrict the local analysis API's file access** — Define whether paths must be user-selected local files or reside in an explicit allowed directory; reject unintended paths.
5. **Harden subprocess invocation** — Pass TShark arguments as a structured argument list, avoid shell evaluation, and test paths with spaces and unusual characters.
6. **Add explicit parser failure categories** — Distinguish invalid capture, unsupported link type, missing TShark, timeout, and malformed TShark output in the API and CLI.
7. **Publish extracted DNS observations in the report** — Either include the already-extracted query-name metadata in a clearly scoped DNS section or remove unused extraction to avoid implying it is reported.
8. **Make API error states visible in the React UI** — Show actionable messages for invalid paths, parser failures, oversized files, and unavailable local API.
9. **Test IPv4/IPv6 and TCP/UDP edge cases** — Include empty captures, incomplete metadata, reversed directions, and timestamp ordering in deterministic fixtures.
10. **Document evidence semantics and limits** — Explain that rule-triggered observations are triage hints, not proof of malicious activity, and identify exactly which metadata is stored.

## Suggested order

Start with file/process safety and automated tests (1–6), then close the reporting/UI and documentation gaps (7–10). Keep fixtures synthetic or from captures the contributor is authorized to analyze.
