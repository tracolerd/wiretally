from dataclasses import dataclass
from typing import Optional
@dataclass
class PacketMetadata:
    """Normalized structure for packet metadata extracted from PCAP."""
    frame_number: int
    time_epoch: float
    frame_len: int
    # Layer 3 (IP)
    ip_src: Optional[str] = None
    ip_dst: Optional[str] = None
    is_ipv6: bool = False
    # Layer 4 (TCP/UDP)
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None  # "TCP" or "UDP"
    tcp_flags: Optional[str] = None
    # Layer 7 (DNS)
    dns_query_name: Optional[str] = None
    @property
    def connection_id(self) -> Optional[str]:
        """Returns a string identifying the bi-directional flow, if IP and ports are present."""
        if not self.ip_src or not self.ip_dst or not self.src_port or not self.dst_port:
            return None
        # Sort to ensure bidirectional traffic gets the same flow ID
        endpoint1 = f"{self.ip_src}:{self.src_port}"
        endpoint2 = f"{self.ip_dst}:{self.dst_port}"
        return f"{self.protocol}|{min(endpoint1, endpoint2)}<->{max(endpoint1, endpoint2)}"
