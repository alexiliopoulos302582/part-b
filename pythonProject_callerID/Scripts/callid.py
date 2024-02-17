from scapy.all import *

def process_packet(packet):
    if IP in packet and UDP in packet and packet.haslayer(Raw):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        udp_sport = packet[UDP].sport
        udp_dport = packet[UDP].dport

        # Check if it's a SIP packet (default SIP port is 5060)
        if udp_dport == 5060 or udp_sport == 5060:
            sip_data = str(packet[Raw].load, 'utf-8', 'ignore')
            print(f"IP Source: {ip_src}, IP Destination: {ip_dst}")
            print(f"UDP Source Port: {udp_sport}, UDP Destination Port: {udp_dport}")
            print("SIP Data:")
            print(sip_data)
            print("=" * 50)

# Replace 'eth0' with the appropriate network interface on your system
sniff(iface='Ethernet', prn=process_packet, store=0, filter="udp port 5060")