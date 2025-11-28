from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}, Destination IP: {ip_layer.dst}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP, Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")

        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP, Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")

        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload: {payload}")

        print("-" * 60)

def main():
    print("Starting packet sniffer...")
    sniff(filter="ip", prn=packet_callback, store=0)

if __name__ == "__main__":
    main()