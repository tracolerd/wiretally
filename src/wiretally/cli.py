import os
import sys
import shutil
import argparse
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from wiretally.validator import validate_capture_file, ValidationError
from wiretally.parser import extract_packet_metadata, ParserError
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
def main():
    parser = argparse.ArgumentParser(description="WireTally - Defensive Network Analysis Workbench")
    parser.add_argument("capture_file", help="Path to the PCAP/PCAPNG capture file")
    args = parser.parse_args()
    print("--- WireTally CLI ---")
    tshark_path = verify_dependencies()
    print(f"[i] Analyzing capture file: {args.capture_file}")
    try:
        validate_capture_file(args.capture_file)
        print("[v] File validation passed.")
        print("[i] Extracting and normalizing packet metadata...")
        packets = extract_packet_metadata(tshark_path, args.capture_file)
        print(f"[v] Successfully extracted {len(packets)} normalized packets.")
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
