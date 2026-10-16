# WireTally Project State
## Mission
Extract useful metadata from local PCAP/PCAPNG files, summarize connection flows and DNS activity, apply transparent rules for defensive network forensics, and generate an evidence-linked JSON/human-readable report. 
## Current Phase: Phase 5 (FastAPI Local Service)
- [x] Phase 0: Repository initialized, Python/TShark env verified.
- [x] Phase 1: Small Python CLI parsing validation.
- [x] Phase 2: Normalized flow/DNS structures (PacketMetadata, FlowRecord).
- [x] Phase 3: Documented rules and evidence-linked JSON report export.
- [x] Phase 4: Input hardening, limits, profiling, and CI testing (graceful truncation handling).
- [x] Phase 5: FastAPI local service integration.
## Next Phases
- **Phase 6:** React timeline/flow visualization.
- **Phase 7:** Optional Nmap export importer; C/C++ evaluation.
## Known Blockers / Risks
- Frontend React implementation requires a separate node environment setup.
