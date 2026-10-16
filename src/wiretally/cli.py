import os
import sys
import shutil
import subprocess
def find_tshark() -> str | None:
    """Locates the TShark executable on the system."""
    # 1. Check system PATH
    tshark_path = shutil.which("tshark")
    if tshark_path:
        return tshark_path
    # 2. Check common Windows installation paths
    common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe"
    ]
    for path in common_paths:
        if os.path.exists(path):
            return path
    return None
def verify_dependencies() -> str:
    """Verifies if TShark is installed and returns its path."""
    tshark_path = find_tshark()
    if not tshark_path:
        print("[!] Error: TShark executable not found on this system.")
        print("[i] WireTally requires TShark (part of Wireshark) to parse capture files.")
        print("[i] Please install it from: https://www.wireshark.org/download.html")
        print("[i] Note: Ensure the 'TShark' option is checked during installation.")
        sys.exit(1)
    try:
        # Run tshark -v to verify execution and get version
        result = subprocess.run([tshark_path, "-v"], capture_output=True, text=True, check=True)
        version_line = result.stdout.splitlines()[0] if result.stdout else "Unknown version"
        print(f"[v] Success: Found {version_line}")
        print(f"[v] Executable Path: {tshark_path}")
        return tshark_path
    except Exception as e:
        print(f"[!] Error executing TShark at {tshark_path}: {e}")
        sys.exit(1)
def main():
    print("--- WireTally CLI ---")
    tshark_path = verify_dependencies()
    print("[i] Environment is ready for packet analysis.")
if __name__ == "__main__":
    main()
