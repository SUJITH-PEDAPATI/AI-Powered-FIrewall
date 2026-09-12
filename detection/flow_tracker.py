"""
detection/flow_tracker.py
AI Firewall — Network flow aggregator.

Reads raw packet records (JSONL) and aggregates them into
bidirectional network flows with computed features.

Can be used two ways:
  1. Import and call  build_flows(packet_log_path) -> list[dict]
  2. Run as a script: python detection/flow_tracker.py
     (writes flows to data/flows.jsonl for offline use)
"""

import json
import os
from datetime import datetime

FILE_PATH   = "logs/security.jsonl"
RESULT_PATH = "data/flows.jsonl"


def build_flows(packet_log_path: str = FILE_PATH) -> list:
    """
    Read captured packets from *packet_log_path* and aggregate into flows.

    A flow is a bidirectional grouping of packets sharing the same
    endpoint pair and protocol.  TCP flag counts and packet-size
    statistics are computed per flow.

    Returns
    -------
    list[dict]
        Each dict contains the flow features expected by the RF model:
        duration, packet_count, total_bytes, min_packet_size,
        max_packet_size, average_packet_size, packets_per_second,
        bytes_per_second, syn_count, ack_count, fin_count, rst_count,
        psh_count — plus identifying fields (IPs, ports, protocol,
        timestamps).
    """
    if not os.path.exists(packet_log_path):
        return []

    flows = {}

    with open(packet_log_path, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                packet = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            # Build a bidirectional flow key so that A→B and B→A are the
            # same flow (matching the original flow_tracker behaviour).
            endpoint1 = (packet.get("source_ip",      ""), packet.get("source_port"))
            endpoint2 = (packet.get("destination_ip", ""), packet.get("destination_port"))
            flow_key  = (min(endpoint1, endpoint2),
                         max(endpoint1, endpoint2),
                         packet.get("protocol"))

            if flow_key not in flows:
                size = packet.get("packet_size", 0) or 0
                flows[flow_key] = {
                    "source_ip":        packet.get("source_ip", ""),
                    "destination_ip":   packet.get("destination_ip", ""),
                    "source_port":      packet.get("source_port"),
                    "destination_port": packet.get("destination_port"),
                    "protocol":         packet.get("protocol"),
                    "start_time":       packet.get("timestamp", ""),
                    "last_seen":        packet.get("timestamp", ""),
                    "min_packet_size":  size,
                    "max_packet_size":  size,
                    "total_packet_size": size,
                    "packet_count":     0,
                    "total_bytes":      0,
                    "syn_count":        0,
                    "ack_count":        0,
                    "fin_count":        0,
                    "rst_count":        0,
                    "psh_count":        0,
                }

            flow  = flows[flow_key]
            size  = packet.get("packet_size", 0) or 0
            flags = packet.get("flags")

            # TCP flag counts (flags may be None for UDP/ICMP)
            if packet.get("protocol") == 6 and flags:
                if "S" in flags: flow["syn_count"] += 1
                if "A" in flags: flow["ack_count"] += 1
                if "F" in flags: flow["fin_count"]  += 1
                if "R" in flags: flow["rst_count"]  += 1
                if "P" in flags: flow["psh_count"]  += 1

            flow["min_packet_size"]   = min(flow["min_packet_size"], size)
            flow["max_packet_size"]   = max(flow["max_packet_size"], size)
            flow["total_packet_size"] += size
            flow["packet_count"]      += 1
            flow["total_bytes"]       += size
            flow["last_seen"]          = packet.get("timestamp", flow["last_seen"])

    # Compute derived features
    result = []
    for flow in flows.values():
        try:
            start    = datetime.strptime(flow["start_time"], "%Y-%m-%d %H:%M:%S.%f")
            end      = datetime.strptime(flow["last_seen"],  "%Y-%m-%d %H:%M:%S.%f")
            duration = (end - start).total_seconds()
        except (ValueError, TypeError):
            duration = 0.0

        pkt_count = max(flow["packet_count"], 1)

        flow["duration"]              = duration
        flow["average_packet_size"]   = flow["total_packet_size"] / pkt_count

        if duration > 0:
            flow["packets_per_second"] = flow["packet_count"] / duration
            flow["bytes_per_second"]   = flow["total_bytes"]  / duration
        else:
            flow["packets_per_second"] = 0.0
            flow["bytes_per_second"]   = 0.0

        result.append(flow)

    return result


# ── script entry-point (backward-compatible) ───────────────────────────────────
if __name__ == "__main__":
    flows = build_flows(FILE_PATH)
    os.makedirs(os.path.dirname(RESULT_PATH), exist_ok=True)

    # Overwrite (not append) so stale data is not mixed with new results.
    with open(RESULT_PATH, "w", encoding="utf-8") as out:
        for flow in flows:
            out.write(json.dumps(flow) + "\n")

    print(f"[FlowTracker] {len(flows)} flows written to {RESULT_PATH}")
