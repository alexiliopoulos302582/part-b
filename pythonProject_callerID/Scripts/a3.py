import webbrowser
from scapy.all import *
import re

# Initialize the phone number variable
phone_number = ""

# Specify the path for the callerid file
callerid_file_path = r'C:\Users\ailiopoulos\Desktop\callerid\callerid.txt'

def extract_phone_number(sip_data):
    from_match = re.search(r'From:\s*"(?P<phone_number>\d+)"', sip_data)
    if from_match:
        return from_match.group('phone_number')
    return None

def write_phone_number_to_file(phone_number):
    with open(callerid_file_path, 'w') as file:
        file.write(phone_number)

def process_packet(packet):
    global phone_number

    if IP in packet and UDP in packet and packet.haslayer(Raw):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        udp_sport = packet[UDP].sport
        udp_dport = packet[UDP].dport

        if udp_dport == 5060:
            sip_data = str(packet[Raw].load, 'utf-8', 'ignore')

            if "INVITE" in sip_data and "180 Ringing" in sip_data:
                phone_number = extract_phone_number(sip_data)
                if phone_number:
                    print(f"Caller's Phone Number: {phone_number}")

                    # Write the phone number to the file
                    write_phone_number_to_file(phone_number)

                    # Process the phone number only once
                    phone_number = None
                    print("-----------------------------------------")
                    print(f"IP Source: {ip_src}, IP Destination: {ip_dst}")
                    print(f"UDP Source Port: {udp_sport}, UDP Destination Port: {udp_dport}")
                    print("SIP Data:")
                    print(sip_data)
                    print("Incoming call: SIP INVITE and 180 Ringing")
                    print("=" * 50)

if __name__ == '__main__':
    # Replace 'Ethernet' with the appropriate network interface on your system
    sniff(iface='Ethernet', prn=process_packet, store=0, filter="udp port 5060")