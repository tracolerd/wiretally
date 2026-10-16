import os
import sys
import shutil
import argparse
import json
from datetime import datetime
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from wiretally.validator import validate_capture_file, ValidationError
from wiretally.parser import extract_packet_metadata, ParserError
from wiretally.analyzer import aggregate_flows
from wiretally.rules import run_all_rules
from wiretally.models import FlowRecord
def find_tshark() -> str | None:
    tshark_path = shutil.which("tshark")
    if tshark_path: return tshark_path
    common_paths = [r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe"]
    for path in common_paths:
        if os.path.exists(path): return path
    return None
def verify_dependencies() -> str:
    tshark_path = find_tshark()
    if not tshark_path:
        print("[!] Error: TShark executable not found on this system.")
        sys.exit(1)
    return tshark_path
def generate_report(capture_name: str, flows: list[FlowRecord], findings: list) -> str:
    """Generates a versioned JSON report."""
    report = {
        "wiretally_version": "0.1.0",
        "schema_version": "1.0",
        "analysis_time": datetime.utcnow().isoformat() + "Z",
        "capture_file": os.path.basename(capture_name),
        "summary": {
            "total_flows": len(flows),
            "total_findings": len(findings)
        },
        "findings": findings
    }
    report_filename = f"wiretally_report_{int(datetime.utcnow().timestamp())}.json"
    with open(report_filename, 'w') as f:
        json.dump(report, f, indent=4)
    return report_filename
def main():
    parser = argparse.ArgumentParser(description="WireTally - Defensive Network Analysis Workbench")
    parser.add_argument("capture_file", help="Path to the PCAP/PCAPNG capture file")
    args = parser.parse_args()
    print("--- WireTally CLI ---")
    tshark_path = verify_dependencies()
    print(f"[i] Analyzing capture file: {args.capture_file}")
    try:
        validate_capture_file(args.capture_file)
        print("[i] Extracting and normalizing packet metadata...")
        packets = extract_packet_metadata(tshark_path, args.capture_file)
        print(f"[v] Successfully extracted {len(packets)} packets.")
        print("[i] Aggregating network flows...")
        flows = aggregate_flows(packets)
        print(f"[v] Discovered {len(flows)} bidirectional flows.")
        print("[i] Applying defensive analysis rules...")
        findings = run_all_rules(flows)
        print(f"[v] Discovered {len(findings)} potential findings.")
        report_file = generate_report(args.capture_file, flows, findings)
        print(f"\n[v] SUCCESS! Report exported to: {report_file}")
    except ValidationError as e:
        print(f"[!] Validation Error: {e}")
        sys.exit(1)
    except ParserError as e:
        print(f"[!] Parser Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected Error: {e}")
        sys.exit(1)
if __name__ == "__main__":
    main()
