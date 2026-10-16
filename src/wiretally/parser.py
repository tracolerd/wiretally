import subprocess
import json
from .models import PacketMetadata
class ParserError(Exception):
    pass
def _get_first_val(layer_dict: dict, key: str):
    """TShark JSON usually returns values as lists. This safely gets the first item."""
    val = layer_dict.get(key)
    if isinstance(val, list) and len(val) > 0:
        return val[0]
    return val
def extract_packet_metadata(tshark_path: str, pcap_path: str) -> list[PacketMetadata]:
    """
    Extracts metadata from a PCAP file using TShark and normalizes it into PacketMetadata objects.
    """
    fields = [
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "frame.len",
        "-e", "ip.src", "-e", "ip.dst", "-e", "ipv6.src", "-e", "ipv6.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.flags",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "dns.qry.name"
    ]
    cmd = [tshark_path, "-r", pcap_path, "-T", "json"] + fields
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0 and not result.stdout.strip():
            raise ParserError(f"TShark processing failed: {result.stderr.strip() if result.stderr else 'Unknown error'}")
        if not result.stdout.strip():
            return []
        try:
            packets = json.loads(result.stdout)
        except json.JSONDecodeError:
            raise ParserError("Failed to parse JSON output from TShark.")
        normalized_packets = []
        for pkt in packets:
            layers = pkt.get("_source", {}).get("layers", {})
            if not layers:
                continue
            try:
                # Basic frame info
                frame_num = int(_get_first_val(layers, "frame.number") or 0)
                time_epoch = float(_get_first_val(layers, "frame.time_epoch") or 0.0)
                frame_len = int(_get_first_val(layers, "frame.len") or 0)
                meta = PacketMetadata(frame_number=frame_num, time_epoch=time_epoch, frame_len=frame_len)
                # IP Layer
                if "ip.src" in layers:
                    meta.ip_src = _get_first_val(layers, "ip.src")
                    meta.ip_dst = _get_first_val(layers, "ip.dst")
                elif "ipv6.src" in layers:
                    meta.ip_src = _get_first_val(layers, "ipv6.src")
                    meta.ip_dst = _get_first_val(layers, "ipv6.dst")
                    meta.is_ipv6 = True
                # Transport Layer
                if "tcp.srcport" in layers:
                    meta.src_port = int(_get_first_val(layers, "tcp.srcport"))
                    meta.dst_port = int(_get_first_val(layers, "tcp.dstport"))
                    meta.protocol = "TCP"
                    meta.tcp_flags = _get_first_val(layers, "tcp.flags")
                elif "udp.srcport" in layers:
                    meta.src_port = int(_get_first_val(layers, "udp.srcport"))
                    meta.dst_port = int(_get_first_val(layers, "udp.dstport"))
                    meta.protocol = "UDP"
                # Application Layer (DNS)
                if "dns.qry.name" in layers:
                    meta.dns_query_name = _get_first_val(layers, "dns.qry.name")
                normalized_packets.append(meta)
            except Exception as parse_err:
                # Skip severely malformed individual packets instead of crashing the whole file
                continue
        if result.stderr.strip() and normalized_packets:
            print(f"[!] Warning from TShark: {result.stderr.strip().splitlines()[-1]}")
        return normalized_packets
    except Exception as e:
        if isinstance(e, ParserError):
            raise e
        raise ParserError(f"Unexpected error during TShark execution: {str(e)}")
