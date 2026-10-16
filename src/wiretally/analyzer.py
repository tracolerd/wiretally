from typing import List, Dict
from .models import PacketMetadata, FlowRecord
def aggregate_flows(packets: List[PacketMetadata]) -> List[FlowRecord]:
    """
    Takes a list of packets and aggregates them into bidirectional flows.
    """
    flows: Dict[str, FlowRecord] = {}
    for pkt in packets:
        cid = pkt.connection_id
        if not cid:
            continue
        if cid not in flows:
            # Extract endpoints from connection_id: "TCP|192.168.1.1:123<->8.8.8.8:443"
            try:
                protocol, endpoints = cid.split('|', 1)
                ep_a, ep_b = endpoints.split('<->', 1)
            except ValueError:
                continue # Safety fallback if connection_id format changes
            flows[cid] = FlowRecord(
                connection_id=cid,
                protocol=protocol,
                endpoint_a=ep_a,
                endpoint_b=ep_b,
                start_time=pkt.time_epoch,
                end_time=pkt.time_epoch,
                total_packets=0,
                total_bytes=0
            )
        # Update existing flow
        flow = flows[cid]
        flow.total_packets += 1
        flow.total_bytes += pkt.frame_len
        flow.end_time = max(flow.end_time, pkt.time_epoch)
        flow.start_time = min(flow.start_time, pkt.time_epoch)
        if pkt.tcp_flags:
            flow.tcp_flags_seen.add(pkt.tcp_flags)
    return list(flows.values())
