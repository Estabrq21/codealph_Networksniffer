from scapy.all import sniff, IP

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        print(f"IP Source: {ip_src}, IP Destination: {ip_dst}")


sniff(prn=packet_callback, store=0, iface="wlan0")  # Replace with your actual network interface
