from scapy.all import *
import random
from time import sleep

dst = raw_input('who is the lucky ip of the day -->')
dport = raw_input('who is the lucky port of the day -->')

l3 = IP(dst = dst)


for i in range(6):
    l4 = TCP(sport = 50100,dport = int(dport),flags = 0x02,seq = random.randint(0,4294967295),ack = 0)
    syn = l3/l4
    sinack = sr1(syn)
    l4 = TCP(sport = 50100,dport = int(dport),flags = 0x10,seq = syn.seq + 1,ack = sinack.seq + 1)
    ack = l3/l4
    send(ack)
    sleep(1)
