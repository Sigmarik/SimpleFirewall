from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet
from scapy.all import IP, UDP, DNS
import xml.etree.ElementTree as ET
import sys

NAME2TYPE = {
    "A": 1,        # Address record (IPv4)
    "NS": 2,       # Name server record
    "MD": 3,       # Mail destination (obsolete)
    "MF": 4,       # Mail forwarder (obsolete)
    "CNAME": 5,    # Canonical name record
    "SOA": 6,      # Start of authority record
    "MB": 7,       # Mailbox domain name (experimental)
    "MG": 8,       # Mail group member (experimental)
    "MR": 9,       # Mail rename domain name (experimental)
    "NULL": 10,    # Null record (experimental)
    "WKS": 11,     # Well-known service record
    "PTR": 12,     # Pointer record
    "HINFO": 13,   # Host information record
    "MINFO": 14,   # Mailbox or mail list information
    "MX": 15,      # Mail exchange record
    "TXT": 16,     # Text record
    "AAAA": 28,    # Address record (IPv6)
    "SRV": 33,     # Service locator
    "NAPTR": 35,   # Naming Authority Pointer
    "ANY": 255     # Any type of record
}

NAME2CLASS = {
    "IN": 1,    # Internet
    "CS": 2,    # CSNET
    "CH": 3,    # CHAOS
    "HS": 4,    # Hesiod
    "ANY": 255   # Any
}

NAME2FLAG = {
    "query": 0,      # Query
    "response": 1    # Response
}

class Rule:
    def __init__(self, action, **kwargs):
        self.action = action
        self.params = kwargs

    def match(self, dns_layer):
        flag = dns_layer.qr
        
        if "flag" in self.params:
            flag_name = self.params["flag"]
            if flag_name not in NAME2FLAG:
                print(f"Incorrect flag name \"{flag_name}\"")
            elif NAME2FLAG[flag_name] != flag:
                return None
            
        if flag == 0:
            return self.match_query(dns_layer)
        else:
            return self.match_response(dns_layer)


    def match_response(self, dns_layer):
        for answer in dns_layer.an:
            if "type" in self.params:
                type_name = self.params["type"]
                if type_name not in NAME2TYPE:
                    print(f"Incorrect type name \"{type_name}\"");
                elif answer.type != NAME2TYPE[type_name]:
                    return None
            if "class" in self.params:
                class_name = self.params["class"]
                if class_name not in NAME2CLASS:
                    print(f"Incorrect class name \"{class_name}\"");
                elif answer.rclass != NAME2CLASS[class_name]:
                    return None
            if "data" in self.params and self.params["data"] != answer.rdata:
                return None
            domain_name = answer.rrname.decode('utf-8')
            print(f"Name: {domain_name}")
            if "name" in self.params and self.params["name"] != domain_name:
                return None
        return self.action


    def match_query(self, dns_layer):
        if "data" in self.params:
            return None

        for question in dns_layer.qd:
            domain_name = question.qname.decode('utf-8')
            print(f"Name: {domain_name}")
            if "name" in self.params and self.params["name"] != domain_name:
                return None
            if "type" in self.params:
                type_name = self.params["type"]
                if type_name not in NAME2TYPE:
                    print(f"Incorrect type name \"{type_name}\"");
                elif question.qtype != NAME2TYPE[type_name]:
                    return None
            if "class" in self.params:
                class_name = self.params["class"]
                if class_name not in NAME2CLASS:
                    print(f"Incorrect class name \"{class_name}\"");
                elif question.qclass != NAME2CLASS[class_name]:
                    return None
        return self.action


class Ruleset:
    def __init__(self, file_name):
        tree = ET.parse(file_name)
        root = tree.getroot()

        self.rules = []

        for rule in root:
            action = rule.tag
            attributes = rule.attrib

            firewall_rule = Rule(action, **attributes)
            self.rules.append(firewall_rule)
    
    def match(self, dns_layer) -> bool:
        rule_id = 0

        for rule in self.rules:
            match = rule.match(dns_layer)
            if match == "block":
                print(f"Blocked by rule {rule_id}")
                return False
            elif match == "allow":
                print(f"Accepted by rule {rule_id}")
                return True
            rule_id += 1
    
        return True

if len(sys.argv) < 2:
    print(f"Usage:\n{sys.argv[0]} [path/to/the/ruleset.xml]")
    exit(1)

rules = Ruleset(sys.argv[1])

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

        if rules.match(dns_layer):
            packet.accept()
        else:
            packet.drop()
    else:
        packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(5, filter)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind() 
