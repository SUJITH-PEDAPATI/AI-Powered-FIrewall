import scapy
from scapy.all import TCP,sniff,UDP,ICMP,IP
from datetime import datetime

class PacketCapture:
    @staticmethod
    def process_packet(self,packet):
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
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport
            flags = str(packet[TCP].flags)

        elif UDP in packet:
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        print(
            f"""
                {timeStamp} | 
                {source_ip}:{source_port} -> {destination_ip}:{destination_port}
                Protocal => {protocol}
                Flags => {flags}
                Size => {packet_size}
            """
        )
print("Starting the packet Capture .....")
packet_capture = PacketCapture()
sniff(prn = packet_capture.process_packet, store = False)

