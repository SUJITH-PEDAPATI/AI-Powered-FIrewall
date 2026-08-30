from scapy.all import TCP,sniff,UDP,ICMP,IP
from datetime import datetime
import os
import json

CAPTURE_TIME = 60
class PacketCapture:
    def __init__(self):
        self.FILE_PATH = "logs/security.jsonl"
        os.makedirs("logs",exist_ok=True)
    
    def process_packet(self, packet):
        if IP not in packet:
            return
        timeStamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")


        source_ip = packet[IP].src ## Capturing the Source IP
        destination_ip = packet[IP].dst ## Capturing the Destination IP
        protocol = packet[IP].proto ## Capturing the Protocal used during Packet Transfer
        packet_size = len(packet) ## Length of the packet 

        source_port = None
        destination_port = None
        flags = None

        if TCP in packet:
            protocol = 6
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            flags = str(packet[TCP].flags)

        elif UDP in packet:
            protocol = 17
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        packet_data = {
            "timestamp" : timeStamp,
            "source_ip" : source_ip,
            "destination_ip": destination_ip,
            "source_port": source_port,
            "destination_port": destination_port,
            "protocol": protocol,
            "packet_size": packet_size,
            "flags": flags
        }

        
        with open(self.FILE_PATH,'a',encoding="utf-8") as file:
            file.write(json.dumps(packet_data) + "\n")
        

if __name__ == "__main__":
    print("Starting the packet Capture .....")
    packet_capture = PacketCapture()
    sniff(
        iface="Wi-Fi", ## Specify the interface to capture packets from
        prn=packet_capture.process_packet, 
        store=False,
        timeout=CAPTURE_TIME
    )
    print("Packet Capturing Completed")

