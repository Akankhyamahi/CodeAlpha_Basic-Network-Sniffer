import csv
import datetime

from scapy.all import sniff, wrpcap
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
csv_file = open("captured_packets.csv", "w", newline="")

csv_writer = csv.writer(csv_file)

csv_writer.writerow([
    "Packet No",
    "Time",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Packet Length"
])
packet_number = 1

def process_packet(packet):
    global packet_number

    if packet.haslayer(IP):

        protocol = packet[IP].proto

        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = "Other"

        print("=" * 60)
        print(f"Packet #{packet_number}")
        print("Time:", datetime.datetime.now().strftime("%H:%M:%S"))
        print("=" * 60)

        print(f"Source IP        : {packet[IP].src}")
        print(f"Destination IP   : {packet[IP].dst}")
        print(f"Protocol         : {protocol_name}")
        print(f"Packet Length    : {len(packet)} bytes")

        source_port = "-"
        destination_port = "-"

        if packet.haslayer(TCP):
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

            print(f"Source Port      : {source_port}")
            print(f"Destination Port : {destination_port}")

        elif packet.haslayer(UDP):
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

            print(f"Source Port      : {source_port}")
            print(f"Destination Port : {destination_port}")

        print("=" * 60)
        print()

        csv_writer.writerow([
            packet_number,
            datetime.datetime.now().strftime("%H:%M:%S"),
            packet[IP].src,
            packet[IP].dst,
            protocol_name,
            source_port,
            destination_port,
            len(packet)
        ])

        packet_number += 1
print("Starting Network Sniffer...")
print("Press Ctrl + C to stop.\n")

captured_packets = sniff(count=20, prn=process_packet)

wrpcap("captured_packets.pcap", captured_packets)

csv_file.close()

print("\nPackets saved successfully!")
print("CSV File  : captured_packets.csv")
print("PCAP File : captured_packets.pcap")
csv_file.close()

print("Packet details saved to captured_packets.csv")