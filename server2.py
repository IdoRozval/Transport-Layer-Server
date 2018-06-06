

###
### IMPORT SECTION
###

from scapy.all import *
import sys
import random


###
### FUNCTIONS
###




def read_data(filename):
    f = open(filename,'rb+')
    data = f.read()
    return data

def write_data(data,filename,purpose):
    f = open(filename,purpose)
    f.write(data)
    f.close()

def change_port(clients):
    sport = int(read_data('sport.txt'))
    data = 'cpt %i' % (sport + 1)   
    for ip,port in clients:
        send_pshack(ip,port,data,clients,False)
    write_data(str(sport + 1),'sport.txt','rb+')


def check_sinflood(ip,port,clients):
    print clients[(ip,port)][2]
    if clients[(ip,port)][2] >= 5:
        del clients[(ip,port)]
        change_port(clients)
        write_data(ip + '*','blacklist.txt','a+')
        print 'SinFlood attack blocked from %s' % ip
    else:
        clients[(ip,port)] = (clients[(ip,port)][0],clients[(ip,port)][1],clients[(ip,port)][2] + 1)
        
                 

def send_sinack(pkt,clients):
    sport = int(read_data('sport.txt'))
    l3 = IP(dst = pkt[IP].src)
    l4 = TCP(dport = pkt[TCP].sport,sport = sport,flags = 0x12,ack = pkt[TCP].seq + 1,seq = random.randint(0,234234))
    synack = l3/l4
    ack = sr1(synack)
    if (pkt[IP].src,pkt[TCP].sport) not in clients:
        clients[(pkt[IP].src,pkt[TCP].sport)] = (ack[TCP].seq,ack[TCP].ack,1)
    else:
        check_sinflood(pkt[IP].src,pkt[TCP].sport,clients)

def send_finack(ip,port,clients):
    sport = int(read_data('sport.txt'))
    ack = clients[(ip,port)][0] + 1
    seq = clients[(ip,port)][1]
    l3 = IP(dst = ip)
    l4 = TCP(dport = port,sport = sport,flags = 0x11,seq = seq,ack = ack)
    finack = l3/l4
    ack = sr1(finack)
    del clients[(ip,port)]

def send_pshack(ip,port,data,clients,flag):
    sport = int(read_data('sport.txt'))
    if flag:
        ack = clients[(ip,port)][0] + len(data)
    else:
        ack = clients[(ip,port)][0]
    seq = clients[(ip,port)][1]
    l3 = IP(dst = ip)
    l4 = TCP(dport = port,sport = sport,flags = 0x18,seq = seq,ack = ack)
    echo = l3/l4/data
    ack = sr1(echo)
    clients[(ip,port)] = (ack[TCP].seq,ack[TCP].ack)
    

def fat_portorican(pkt,clients):
    sport = int(read_data('sport.txt'))
    blacklist = (read_data('blacklist.txt')).split('*')   
    print sport,blacklist
    if pkt[TCP].sport == sport or pkt[TCP].dport != sport or pkt[IP].src in blacklist:
        pass
    elif pkt[TCP].flags == 0x02: # SYN
        send_sinack(pkt,clients)
    elif pkt[TCP].flags == 0x11: # FIN_ACK
        send_finack(pkt[IP].src,pkt[TCP].sport,clients)
    elif pkt[TCP].flags == 0x18: # PSH_ACK
        send_pshack(pkt[IP].src,pkt[TCP].sport,pkt.load,clients,True)
    
        
        
        
        
        
        

###
### MAIN
###
'''
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80
'''
print 'Ready'
clients = {}

write_data('50000','sport.txt','rb+')

sniff(prn = lambda x: fat_portorican(x,clients),filter = 'tcp')
   
    

            




    
