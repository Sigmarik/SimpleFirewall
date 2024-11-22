from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet
from scapy.all import IP, UDP, DNS

def filter(packet):
    scapy_packet = IP(packet.get_payload())

    if scapy_packet.haslayer(UDP) and scapy_packet.haslayer(DNS):
        dns_layer = scapy_packet.getlayer(DNS)

        dns_id = dns_layer.id
        dns_qdcount = dns_layer.qdcount
        dns_ancount = dns_layer.ancount
        dns_nscount = dns_layer.nscount
        dns_arcount = dns_layer.arcount

        print(f"DNS ID: {dns_id}")
        print(f"Questions Count: {dns_qdcount}")
        print(f"Answer Count: {dns_ancount}")
        print(f"Authority Count: {dns_nscount}")
        print(f"Additional Count: {dns_arcount}")

    packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(5, filter)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind() 
