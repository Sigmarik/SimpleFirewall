from netfilterqueue import NetfilterQueue
from netfilterqueue import Packet

def print_and_accept(pkt: Packet):
    print(pkt)
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(5, print_and_accept)
try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind() 
