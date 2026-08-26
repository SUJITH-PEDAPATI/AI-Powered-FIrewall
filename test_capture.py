from scapy.all import sniff

print("Starting capture for 10 seconds...")

def packet_received(packet):
    print(packet.summary())

sniff(
    iface="Wi-Fi",
    prn=packet_received,
    store=False,
    timeout=10
)

print("Capture finished.")