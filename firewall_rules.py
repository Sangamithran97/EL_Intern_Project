# Step 1: Imports
from scapy.all import sniff
from datetime import datetime

# Step 2: Define Firewall Rules
firewall_rules = {
    "block_ips": ["192.168.1.10"],
    "block_ports": [21, 23, 4444],
    "block_protocols": ["ICMP"]
}

# Step 6: Logging Function
def log_packet(packet, reason):
    with open("firewall_logs.txt", "a") as f:
        f.write(f"{datetime.now()} - {reason} - {packet.summary()}\n")

# Step 4: Packet Filtering Callback
def packet_callback(packet):
    ip_layer = packet.getlayer("IP")
    if ip_layer:
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if src_ip in firewall_rules["block_ips"] or dst_ip in firewall_rules["block_ips"]:
            print(f"❌ Blocked packet from/to {src_ip}/{dst_ip}")
            log_packet(packet, "Blocked IP")
            return

        if packet.haslayer("TCP") and packet["TCP"].dport in firewall_rules["block_ports"]:
            print(f"❌ Blocked TCP port {packet['TCP'].dport}")
            log_packet(packet, "Blocked TCP port")
            return

        if packet.haslayer("UDP") and packet["UDP"].dport in firewall_rules["block_ports"]:
            print(f"❌ Blocked UDP port {packet['UDP'].dport}")
            log_packet(packet, "Blocked UDP port")
            return

        if packet.haslayer("ICMP") and "ICMP" in firewall_rules["block_protocols"]:
            print("❌ Blocked ICMP packet")
            log_packet(packet, "Blocked ICMP")
            return

    print(f"✅ Allowed: {packet.summary()}")

# Step 3: Start Packet Sniffing
sniff(prn=packet_callback, store=0)
