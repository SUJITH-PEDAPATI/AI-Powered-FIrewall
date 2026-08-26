import json
import os
from datetime import datetime

FILE_PATH = "logs/security.jsonl"
RESULT_PATH = "data/flows.jsonl"
flows = {} 
with open(FILE_PATH,'r') as file:
    for line in file:
        packet = json.loads(line)

        """In the below, Our System considers the communication between:
        between 2 IPs :
            192.168.1.10:50000 -----> 8.8.8.8:443
                8.8.8.8:443 ------> 192.168.1.10:50000
        are treated as different protocals,
        # flow_key = (
        #     packet['source_ip'],
        #     packet['destination_ip'],
        #     packet['source_port'],
        #     packet['destination_port'],
        #     packet['protocol']
        # ) """

        endpoint1 = (
            packet["source_ip"],
            packet["source_port"]
        )   
        endpoint2 = (
            packet["destination_ip"],
            packet["destination_port"]
        )

        flow_key = (
            min(endpoint1,endpoint2),
            max(endpoint1,endpoint2),
            packet["protocol"]
        )

        if flow_key not in flows:
            flows[flow_key] = {
                "source_ip": packet['source_ip'],
                "destination_ip" : packet['destination_ip'],
                "source_port": packet['source_port'],
                "destination_port": packet['destination_port'],
                "protocol": packet['protocol'],
                "start_time": packet['timestamp'],
                "last_seen": packet['timestamp'],
                "min_packet_size": packet['packet_size'],
                "max_packet_size": packet['packet_size'],
                "total_packet_size": packet['packet_size'],
                "packet_count": 0,
                "total_bytes": 0,
                "syn_count" : 0,
                "ack_count" : 0,
                "fin_count": 0,
                "rst_count": 0,
                "psh_count": 0
            }
        flags = packet['flags']
        if packet['protocol'] == 6:
            if "S" in flags:
                flows[flow_key]["syn_count"] += 1
            if "A" in flags:
                flows[flow_key]["ack_count"] += 1
            if "F" in flags:
                flows[flow_key]["fin_count"] += 1
            if "R" in flags:
                flows[flow_key]["rst_count"] += 1
            if "P" in flags:
                flows[flow_key]["psh_count"] += 1

        size = packet['packet_size']

        flows[flow_key]['min_packet_size'] = min(flows[flow_key]['min_packet_size'],size)

        flows[flow_key]['max_packet_size'] = max(flows[flow_key]['max_packet_size'],size)

        flows[flow_key]['total_packet_size'] += size
        flows[flow_key]['packet_count'] += 1
        flows[flow_key]['total_bytes'] += packet['packet_size']
        flows[flow_key]['last_seen'] = packet['timestamp']

os.makedirs(os.path.dirname(RESULT_PATH), exist_ok=True)

for key,flow in flows.items():
    start = datetime.strptime(
        flow['start_time'],
        "%Y-%m-%d %H:%M:%S.%f"
    )

    end = datetime.strptime(
        flow['last_seen'],
        "%Y-%m-%d %H:%M:%S.%f"
    )

    flow['duration'] = (end-start).total_seconds()

    flow['average_size'] = (flow['total_packet_size']/flow['packet_count'])

    if ( flow['duration'] > 0):
        flow['packets_per_second'] = (flow['packet_count']/flow['duration'])
        flow['bytes_per_second'] = (flow['total_bytes']/flow['duration'])
    else:
        flow['packets_per_second'] = 0
        flow['bytes_per_second'] = 0
    with open(RESULT_PATH,'a') as file:
        file.write(json.dumps(flow) + "\n")
    
