from typing import List, Dict, Any
from .models import FlowRecord
class Rule:
    rule_id = "WT-000"
    name = "Base Rule"
    severity = "INFO"
    description = ""
    false_positives = ""
    @classmethod
    def evaluate(cls, flows: List[FlowRecord]) -> List[Dict[str, Any]]:
        raise NotImplementedError
class WT001_HighVolumeTransfer(Rule):
    rule_id = "WT-001"
    name = "High Volume Data Transfer"
    severity = "MEDIUM"
    description = "Detects a single bidirectional flow transferring more than 10MB of data."
    false_positives = "File downloads, video streaming, or large backups will trigger this."
    @classmethod
    def evaluate(cls, flows: List[FlowRecord]) -> List[Dict[str, Any]]:
        findings = []
        THRESHOLD_BYTES = 10 * 1024 * 1024  # 10 MB
        for flow in flows:
            if flow.total_bytes > THRESHOLD_BYTES:
                findings.append({
                    "rule_id": cls.rule_id,
                    "name": cls.name,
                    "severity": cls.severity,
                    "description": cls.description,
                    "false_positives": cls.false_positives,
                    "evidence": {
                        "connection_id": flow.connection_id,
                        "total_bytes_transferred": flow.total_bytes,
                        "start_time": flow.start_time,
                        "end_time": flow.end_time
                    }
                })
        return findings
class WT002_SuspiciousPorts(Rule):
    rule_id = "WT-002"
    name = "Suspicious Common Ports"
    severity = "LOW"
    description = "Detects connections to ports often used by malware (e.g., 4444, 3389 without justification)."
    false_positives = "Legitimate administrative use of RDP (3389) or internal developer servers."
    @classmethod
    def evaluate(cls, flows: List[FlowRecord]) -> List[Dict[str, Any]]:
        findings = []
        SUSPICIOUS_PORTS = {"4444", "3389", "6667"} # Metasploit default, RDP, IRC
        for flow in flows:
            # Extract ports from endpoints (e.g., 192.168.1.1:3389)
            ep_a_port = flow.endpoint_a.split(':')[-1]
            ep_b_port = flow.endpoint_b.split(':')[-1]
            matched_ports = SUSPICIOUS_PORTS.intersection({ep_a_port, ep_b_port})
            if matched_ports:
                findings.append({
                    "rule_id": cls.rule_id,
                    "name": cls.name,
                    "severity": cls.severity,
                    "description": cls.description,
                    "false_positives": cls.false_positives,
                    "evidence": {
                        "connection_id": flow.connection_id,
                        "suspicious_ports_detected": list(matched_ports),
                        "start_time": flow.start_time
                    }
                })
        return findings
def run_all_rules(flows: List[FlowRecord]) -> List[Dict[str, Any]]:
    """Runs all registered rules against the aggregated flows."""
    all_findings = []
    rules = [WT001_HighVolumeTransfer, WT002_SuspiciousPorts]
    for rule in rules:
        all_findings.extend(rule.evaluate(flows))
    return all_findings
