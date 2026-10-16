# WireTally

**A defensive workbench for investigating network traffic and preserving useful evidence.**

WireTally is a planned network traffic analysis application for offline PCAP investigation. It is intended to help a learner or analyst explore connection flows, DNS activity, protocol distribution, and rule-based anomalies without treating every unusual packet as proof of compromise.

> **Project status:** Initial planning and repository setup. The parser workflow, API, UI, and detection rules are not implemented yet.

## Problem

Packet captures can contain large amounts of low-level information. During an investigation, analysts often need a repeatable summary of which hosts communicated, which protocols appeared, what DNS names were queried, and which observations warrant closer inspection.

WireTally aims to transform an approved capture into structured findings and a reviewable timeline while preserving the limits of what the evidence can prove.

## Project principles

- **Offline-first analysis:** The initial version processes supplied PCAP files; live capture is not required.
- **Evidence before labels:** Findings should include the data and rule that triggered them.
- **Defensive use:** Use only captures and systems that the user owns or is authorized to analyze.
- **Bounded processing:** Treat PCAP files as untrusted input and apply resource limits.
- **Modular parsers:** Reuse established packet-analysis tools instead of building a full protocol dissector unnecessarily.

## Planned MVP

- Accept a PCAP or PCAPNG file through a local workflow.
- Validate input and return actionable errors for unsupported or malformed captures.
- Summarize protocols, endpoints, ports, timestamps, and connection flows.
- Extract available DNS query/response metadata.
- Apply a small, documented set of deterministic anomaly rules.
- Show findings with timestamps, relevant flow metadata, and rule explanations.
- Export a structured JSON report and a human-readable investigation summary.

A detected anomaly is a lead for investigation, not a verdict that a device is compromised.

## Proposed architecture

~~~mermaid
flowchart TD
    A[PCAP or PCAPNG] --> B[Input Validation and Limits]
    B --> C[Packet Metadata Extraction]
    C --> D[Flow and DNS Aggregation]
    D --> E[Documented Detection Rules]
    E --> F[Findings with Evidence]
    F --> G[JSON and Summary Export]
    F --> H[Future Web Dashboard]
~~~

The first version should separate file handling, parser invocation, normalization, analysis rules, and reporting. This makes the rule engine testable without requiring every test to process a large capture.

## Proposed technology

| Area | Planned choice |
|---|---|
| Analysis and orchestration | Python |
| Packet parsing | TShark/Wireshark or an appropriate maintained Python library |
| Local API | FastAPI, after the analysis workflow is stable |
| Dashboard | React and TypeScript |
| Structured output | JSON; optional SQL storage later |
| Performance-critical component | C/C++ only if profiling demonstrates a concrete need |
| Optional scan data | A validated importer for authorized Nmap exports |

TShark may be installed as a separate dependency. The project should check whether it is available and explain how to configure it rather than silently assuming it exists.

## Planned analysis areas

### Connection and flow summaries

Group packet metadata into useful conversations and show observed endpoints, ports, protocol, first/last timestamps, and packet/byte counts where those fields can be derived reliably.

### DNS investigation

Summarize queried names, response codes, and related hosts when the capture contains the necessary evidence. A DNS query alone should not be interpreted as malicious.

### Rule-based observations

Start with transparent rules such as unusual port patterns or repeated failed DNS responses only when the required fields are available. Every rule should specify its inputs, limitations, and expected false positives.

### Reports

Each finding should carry a stable identifier, timestamp or time range, affected flow, rule ID, evidence summary, and caveat. Avoid embedding sensitive packet payloads in reports by default.

## Development roadmap

1. Build a small Python analysis command for approved sample captures.
2. Define normalized data models for packets, flows, DNS events, and findings.
3. Add fixtures and unit tests for extraction and aggregation.
4. Add detection rules with explicit rationale and negative tests.
5. Expose a local FastAPI endpoint once command-line behavior is stable.
6. Build a React dashboard and investigation timeline.
7. Add an authorized scan-result importer.
8. Consider C/C++ optimization only after measuring a real bottleneck.

## Testing plan

- Known-good sample captures with documented expected summaries.
- Empty, malformed, truncated, and unsupported input files.
- Missing TShark executable and parser failure cases.
- Time-zone and timestamp boundary cases.
- Duplicate packets, fragmented traffic, and incomplete TCP conversations where applicable.
- Rule-level positive and negative fixtures.
- Size and runtime limits for uploaded files.
- Regression tests that compare stable portions of generated reports.

Test data must be synthetic, publicly licensed, or otherwise authorized for use.

## Security and privacy

PCAP files can contain personal information, internal addresses, authentication artifacts, and other sensitive payloads. Keep payload extraction off by default, document retention behavior, impose size/time limits, and avoid logging sensitive data. Do not use the application to capture or investigate traffic without authorization.

## Current status

This repository currently contains the project brief and license. No packet-processing pipeline, detection engine, frontend, or verified performance result is available yet.

## License

MIT. See [LICENSE](LICENSE).
