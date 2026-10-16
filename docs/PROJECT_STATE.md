# WireTally Project State
## Mission
Extract useful metadata from local PCAP/PCAPNG files, summarize connection flows and DNS activity, apply transparent rules for defensive network forensics, and generate an evidence-linked JSON/human-readable report. 
## Current Phase: Phase 0 (Environment Setup)
- [x] Repository initialized and cloned.
- [x] Python 3.14.x environment verified.
- [ ] TShark parser availability configured and verified.
- [x] Documentation framework established (`PROJECT_STATE.md`, `DECISIONS.md`).
## Next Phases
- **Phase 1:** Small Python CLI processing a known sample file.
- **Phase 2:** Normalized flow/DNS structures and unit tests.
- **Phase 3:** Documented rules and evidence-linked report.
- **Phase 4:** Input hardening, limits, profiling, and CI.
- **Phase 5:** FastAPI local service.
- **Phase 6:** React timeline/flow visualization.
- **Phase 7:** Optional Nmap export importer; C/C++ evaluation.
## Known Blockers / Risks
- TShark availability on Windows host; need dynamic path resolution or PATH environment configuration.
