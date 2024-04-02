from scapy.all import *

def packet_analysis(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        payload = packet[Raw].load.lower()
        if b'user' in payload or b'pass' in payload:
        # ймовірно містить дані для авторизації
            print(f"Potential sensitive data transfer detected from {packet[IP].src} to {packet[IP].dst}")

# Запуск моніторингу мережевого трафіку
sniff(filter="tcp", prn=packet_analysis, store=0, count=100)