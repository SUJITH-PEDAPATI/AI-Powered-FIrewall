## Building the first real - time AI detection Component
import json
import joblib
import pandas
from scapy.all import TCP,UDP,sniff,ICMP,IP
from datetime import datetime
from collections import defaultdict
import time
from risk_engine import RiskEngine
from decision_engine import DecisionEngine
from firewall.windows_firewall import WindowsFirewall


MODEL_PATH = "ai/firewall_model.pkl"
INTERFACE = "Wi-Fi"
FLOW_TIMEOUT = 60
DETECTION_WINDOW = 5

features = [
    "duration",
    "packet_count",
    "total_bytes",
    "min_packet_size",
    "max_packet_size",
    "average_packet_size",
    "packets_per_second",
    "bytes_per_second",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count"
]

model = joblib.load(MODEL_PATH)
flows = {}
riskEngine = RiskEngine()
decisionEngine = DecisionEngine()
windowsfirewall = WindowsFirewall()
source_activity = defaultdict(
    lambda: {
        "window_start": time.time(),
        "last_seen": time.time(),
        "syn_count": 0,
        "rst_count": 0,
        "ports": set(),
        "packet_count": 0
    }
)
class LiveDetector:
    def __init__(self):
        pass

    def get_flow_key(self,packet):
        if IP not in packet:
            return None

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        if TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"
            source_port = 0
            destination_port = 0

        else:
            return None
        return (
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            protocol
        )

    def create_flow(self,packet):
        now = datetime.now()
        size = len(packet)

        return {
            "start_time": now,
            "last_time": now,
            "packet_count": 1,
            "total_bytes": size,
            "min_packet_size": size,
            "max_packet_size": size,
            "syn_count": 0,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
            "psh_count": 0
        }

    def update_flow(self,flow,packet):
        now = datetime.now()
        size = len(packet)

        flow["last_time"] = now
        flow["packet_count"] += 1
        flow["total_bytes"] += size

        flow["min_packet_size"] = min( flow["min_packet_size"],size)
        flow["max_packet_size"] = max(flow["max_packet_size"],size)

        if TCP in packet:
            flags = packet[TCP].flags
            if "S" in flags:
                flow["syn_count"] += 1
            if "A" in flags:
                flow["ack_count"] += 1
            if "F" in flags:
                flow["fin_count"] += 1
            if "R" in flags:
                flow["rst_count"] += 1
            if "P" in flags:
                flow["psh_count"] += 1

    def calculate_features(self,flow):
        duration = (flow["last_time"]-flow["start_time"]).total_seconds()
        if duration <= 0:
            duration = 0.0001

        packet_count = flow["packet_count"]
        total_bytes = flow["total_bytes"]

        average_bytes = (total_bytes/packet_count)
        packets_per_second = (packet_count/duration)
        bytes_per_second = (total_bytes/duration)

        return {
            "duration": duration,
            "packet_count":packet_count,
            "total_bytes":total_bytes,
            "min_packet_size":flow['min_packet_size'],
            "max_packet_size": flow['max_packet_size'],
            "average_packet_size": average_bytes,
            "packets_per_second":packets_per_second,
            "bytes_per_second": bytes_per_second,
            "syn_count": flow["syn_count"],
            "ack_count": flow["ack_count"],
            "fin_count": flow["fin_count"],
            "rst_count": flow["rst_count"],
            "psh_count": flow["psh_count"]
        }

    def predict_flow(self, flow_key, flow):
        data = self.calculate_features(flow)
        dataFrame = pandas.DataFrame(
            [[data[feature] for feature in features]],
            columns=features
        )
        prediction = model.predict(dataFrame)[0]
        source_ip = flow_key[0]
        behavioral_risk = self.get_behavioral_risk(
            source_ip
        )
        decision = decisionEngine.decide(
            prediction,
            behavioral_risk
        )
        
        print("\n" + "=" * 60)
        print("AI FIREWALL DECISION")
        print("=" * 60)

        print("Source IP        :", source_ip)
        print("AI Prediction    :", prediction)
        print("Behavior Risk    :", behavioral_risk)
        print("FINAL DECISION   :", decision)
        if decision == "BLOCK":
            windowsfirewall.block_ip(source_ip)
        print("=" * 60)

    def process_packet(self, packet):
        flow_key = self.get_flow_key(packet)
        if flow_key is None:
            return

        if flow_key not in flows:
            flows[flow_key] = self.create_flow(packet)
        else:
            self.update_flow(
                flows[flow_key],
                packet
            )
        flow = flows[flow_key]
        current_time = datetime.now()
        duration = (
            current_time - flow["start_time"]
        ).total_seconds()

        if duration >= FLOW_TIMEOUT:
            self.predict_flow(
                flow_key,
                flow
            )
            del flows[flow_key]
        self.track_source_activity(packet)

    def get_behavioral_risk(self, source_ip):

        activity = source_activity[source_ip]
        unique_ports = len(activity["ports"])
        syn_count = activity["syn_count"]
        rst_count = activity["rst_count"]
        packets_per_second = (
            activity["packet_count"] / DETECTION_WINDOW
        )
        risk = riskEngine.calculate_risk(
            syn_count,
            unique_ports,
            packets_per_second,
            rst_count
        )
        return risk
    def track_source_activity(self,packet):
        if IP not in packet : return
        source_ip = packet[IP].src
        activity = source_activity[source_ip]

        activity["last_seen"] = time.time()
        activity["packet_count"] += 1
        current_time = time.time()
        if current_time - activity["window_start"] >= DETECTION_WINDOW:
            self.detect_port_scan(source_ip)

            # Start a new window
            activity["window_start"] = current_time
            activity["syn_count"] = 0
            activity["rst_count"] = 0
            activity["ports"].clear()
            activity["packet_count"] = 0

        activity["packet_count"] += 1
        if TCP in packet:
            destination_port = packet[TCP].dport
            activity["ports"].add(destination_port)

            flags = packet[TCP].flags

            if "S" in flags:
                activity["syn_count"] += 1
            if "R" in flags:
                activity["rst_count"] += 1

    def detect_port_scan(self,source_ip):
        activity = source_activity[source_ip]
        duration = (activity["last_seen"]-activity["first_seen"])
        if duration <= 0:
            duration = 1

        unique_ports = len(activity["ports"])
        syn_count = activity["syn_count"]
        packets_per_second = activity["packet_count"]/duration

        rst_count = activity["rst_count"]
        risk = riskEngine.calculate_risk(
            syn_count,
            unique_ports,
            packets_per_second,
            rst_count
        )

        print("Source IP       :", source_ip)
        print("SYN packets     :", syn_count)
        print("Unique ports    :", unique_ports)
        print("Packets/sec     :", packets_per_second)
        print("Risk Score      :", risk)

        if risk >= 0.8:
            print("Possible Port Scan")

        elif risk >= 0.5:
            print("SUSPICIOUS")

        else:
            print("✓ NORMAL")

        print("=" * 60)


sniff(
    iface = INTERFACE,
    prn = LiveDetector().process_packet,
    store = False
)


    


