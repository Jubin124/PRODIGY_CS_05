from scapy.all import sniff, IP, TCP, UDP

t
def analyze_packet(packet):
   
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        
      
        proto_name = "TCP" if protocol == 6 else "UDP" if protocol == 17 else "Other"
        
        print(f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {proto_name}")
        
       
        if proto_name in ["TCP", "UDP"]:
            try:
                payload = bytes(packet[proto_name].payload).decode('utf-8', 'ignore')
                print(f"Payload: {payload}\n" if payload else "Payload: None\n")
            except Exception as e:
                print(f"Error decoding payload: {e}\n")


def start_sniffer():
    print("Starting Packet Sniffer... (Press Ctrl+C to stop)")
    sniff(prn=analyze_packet, filter="ip", store=False)

if __name__ == "__main__":
    start_sniffer()

