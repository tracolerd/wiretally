# Architectural Decisions Record (ADR)
## 001 - Choice of Packet Parsing Engine
**Date:** 2026-10-16
**Status:** Accepted
**Context:** 
We need to parse PCAP/PCAPNG files locally on Windows. Building a custom dissector is explicitly out of scope. We evaluated using native Python bindings (like `dpkt` or `scapy`), wrappers like `pyshark`, or directly calling the TShark CLI.
**Decision:** 
We will use the TShark CLI directly via Python's `subprocess` module, exporting packet data as JSON (`tshark -T json`). 
**Rationale:**
1. TShark has highly mature and accurate protocol dissectors.
2. `pyshark` often introduces async complexity and memory leaks for larger captures.
3. Calling `subprocess` keeps our dependencies light and standard library-focused.
**Consequences:**
- The target system must have Wireshark/TShark installed.
- Our tool must explicitly validate the existence and version of the `tshark` executable before processing.
