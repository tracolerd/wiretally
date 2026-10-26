"""Extract packet metadata from PCAP files through TShark."""

import json
import subprocess

from .models import PacketMetadata


DEFAULT_TSHARK_TIMEOUT_SECONDS = 60


class ParserError(Exception):
    """Raised when TShark output cannot be processed safely.

    The stable code attribute is intended for API consumers; error text is
    for humans and may change as diagnostics improve.
    """

    def __init__(self, message: str, code: str = "parser_error") -> None:
        super().__init__(message)
        self.code = code


def _get_first_val(layer_dict: dict, key: str):
    """TShark JSON usually returns values as lists; safely get the first item."""
    value = layer_dict.get(key)
    if isinstance(value, list) and value:
        return value[0]
    return value


def extract_packet_metadata(
    tshark_path: str,
    pcap_path: str,
    timeout_seconds: int = DEFAULT_TSHARK_TIMEOUT_SECONDS,
) -> list[PacketMetadata]:
    """Extract selected packet metadata with a bounded TShark runtime."""
    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be greater than zero")

    fields = [
        "-e", "frame.number", "-e", "frame.time_epoch", "-e", "frame.len",
        "-e", "ip.src", "-e", "ip.dst", "-e", "ipv6.src", "-e", "ipv6.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.flags",
        "-e", "udp.srcport", "-e", "udp.dstport", "-e", "dns.qry.name",
    ]
    cmd = [tshark_path, "-r", pcap_path, "-T", "json", *fields]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise ParserError(
            f"TShark analysis exceeded the {timeout_seconds}-second timeout.",
            code="tshark_timeout",
        ) from exc
    except OSError as exc:
        # Avoid returning raw command arguments or local path details to callers.
        raise ParserError(
            "Unable to start TShark. Verify its installation and configuration.",
            code="tshark_unavailable",
        ) from exc
    except Exception as exc:
        raise ParserError("Unexpected error while starting TShark.", code="tshark_execution_error") from exc

    if result.returncode != 0:
        # Do not treat partial JSON output as a successful analysis. Avoid
        # returning raw stderr, which can contain local paths or environment data.
        raise ParserError(
            f"TShark processing failed with exit code {result.returncode}.",
            code="tshark_failed",
        )
    if not result.stdout.strip():
        return []

    try:
        packets = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ParserError("Failed to parse JSON output from TShark.", code="tshark_invalid_json") from exc

    normalized_packets: list[PacketMetadata] = []
    for packet in packets:
        layers = packet.get("_source", {}).get("layers", {})
        if not layers:
            continue
        try:
            frame_num = int(_get_first_val(layers, "frame.number") or 0)
            time_epoch = float(_get_first_val(layers, "frame.time_epoch") or 0.0)
            frame_len = int(_get_first_val(layers, "frame.len") or 0)
            meta = PacketMetadata(
                frame_number=frame_num,
                time_epoch=time_epoch,
                frame_len=frame_len,
            )

            if "ip.src" in layers:
                meta.ip_src = _get_first_val(layers, "ip.src")
                meta.ip_dst = _get_first_val(layers, "ip.dst")
            elif "ipv6.src" in layers:
                meta.ip_src = _get_first_val(layers, "ipv6.src")
                meta.ip_dst = _get_first_val(layers, "ipv6.dst")
                meta.is_ipv6 = True

            if "tcp.srcport" in layers:
                meta.src_port = int(_get_first_val(layers, "tcp.srcport"))
                meta.dst_port = int(_get_first_val(layers, "tcp.dstport"))
                meta.protocol = "TCP"
                meta.tcp_flags = _get_first_val(layers, "tcp.flags")
            elif "udp.srcport" in layers:
                meta.src_port = int(_get_first_val(layers, "udp.srcport"))
                meta.dst_port = int(_get_first_val(layers, "udp.dstport"))
                meta.protocol = "UDP"

            if "dns.qry.name" in layers:
                meta.dns_query_name = _get_first_val(layers, "dns.qry.name")

            normalized_packets.append(meta)
        except (TypeError, ValueError, KeyError):
            # Skip a malformed individual packet without discarding the capture.
            continue

    if result.stderr.strip() and normalized_packets:
        print(f"[!] Warning from TShark: {result.stderr.strip().splitlines()[-1]}")
    return normalized_packets
