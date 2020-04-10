#!/usr/local/bin/python

from scapy.all import *
import argparse

load_layer("tls")
load_layer("http")

payload_len = 0

def process_pcap(pcap):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    global sequence_number
    global acknowledgement_number
    global timestamp
    global payload_len
    query = 1
    layer = 0
    match=0

    if not args.Ether and not args.IP and not args.UDP and not args.ARP and not args.TCP and not args.DNS and not args.TLS and not args.HTTP and not args.IP_SRC and not args.IP_DST:
        query=None
    if args.ARP and pcap.haslayer(ARP):
        layer=2
    if args.IP and pcap.haslayer(IP):
        layer=3
    if args.TCP and pcap.haslayer(TCP):
        layer=4    
    if args.UDP and pcap.haslayer(UDP):
        layer=4     
    if args.DNS and pcap.haslayer(DNS):
        layer=7
    if args.TLS and pcap.haslayer(TLS):
        layer=7
    if args.HTTP and pcap.haslayer(HTTP):
        layer=7
    
    if pcap.haslayer(IP) and (pcap[IP].src==args.IP_SRC or pcap[IP].dst==args.IP_DST):
        match=1

    if pcap.haslayer(Ether):
        if not query or args.Ether or layer > 1 or match==1:
            print ("\r\nEther Src: " + pcap[Ether].src + " - Ether Dst: " + pcap[Ether].dst + " - Ether Type: " + str(hex(pcap[Ether].type)))
    

    if pcap.haslayer(IP):
        if not query or args.IP or layer > 2 or match==1:
            print ("IP Src: " + pcap[IP].src + " - IP Dst: " + pcap[IP].dst + " - IP ID: " + str(pcap[IP].id) + " - TTL: " + str(pcap[IP].ttl))
        

    if pcap.haslayer(UDP):
        if not query or args.UDP or layer > 3 or match==1:
            print ("UDP - Source Port: " + str(pcap[UDP].sport) + "  Destination Port: " + str(pcap[UDP].dport))   
        

    if pcap.haslayer(TCP):
        sequence_number = pcap[TCP].seq
        acknowledgement_number = pcap[TCP].ack
        timestamp = pcap[TCP].time
        payload_len += len(pcap[TCP].payload)
        if not query or args.TCP or layer > 3 or match==1:
        
        
            print ("TCP - Source Port: " + str(pcap[TCP].sport) + "  Destination Port: " + str(pcap[TCP].dport))
            print ("Response seq: " + str(sequence_number) + " ack: " + \
                str(acknowledgement_number) + " timestamp: " + str(timestamp) + " len: " + \
                str(len(pcap[TCP].payload)) + " window: " + str(pcap[TCP].window) + " options: " + str(pcap[TCP].options))
            F = pcap['TCP'].flags    
            print ("Flags: ")
            if F & FIN:
                print ("FIN")
            if F & SYN:
                print ("SYN")
            if F & RST:
                print ("RST")
            if F & ACK:
                print ("ACK")
            if F & PSH:
                print ("PSH")
            if F & URG:
                print ("URG")       
            if F & ECE:
                print ("ECE")
            if F & CWR:
                print ("CWR")
                   

    if pcap.haslayer(HTTP):  
        if not query or args.HTTP or layer > 4 or match==1:
            print ("HTTP - " + str(pcap[HTTP]))
        

    if pcap.haslayer(ARP):  
        if not query or args.ARP or layer > 1 or match==1: 
            print ("ARP - "  + "Hardware Source: " + pcap[ARP].hwsrc + " -  Source Addr: " + pcap[ARP].psrc + " - op: " + str(pcap[ARP].op))
        

    if pcap.haslayer(DNS):
        if not query or args.DNS or layer > 4 or match==1:   
            print ("DNS - "  + str(pcap[DNS].qd), str(pcap[DNS].an), str(pcap[DNS].ns), str(pcap[DNS].ar) + "\r\n")
    

    if pcap.haslayer(TLS): 
        if not query or args.TLS or layer > 4 or match==1:  
            print ("TLS - "  + "Type: " + str(pcap[TLS].type) + " -  Version: " + str(pcap[TLS].version))
            if "TLSApplicationData" not in  str(pcap[TLS].msg):
                print (" -  Message: " + str(pcap[TLS].msg))
          

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--read", help="read pcapfile",action="store", dest="pcap", required=True)
parser.add_argument("-e", "--ether", help="Query Layer 2 protocol",action="store_true", dest="Ether")
parser.add_argument("-i", "--ip", help="Query IP protocol",action="store_true", dest="IP")
parser.add_argument("-is", "--ip_source", help="Query for IP source",action="store", dest="IP_SRC")
parser.add_argument("-id", "--ip_dest", help="Query for IP destination",action="store", dest="IP_DST")
parser.add_argument("-u", "--udp", help="Query UDP protocol",action="store_true", dest="UDP")
parser.add_argument("-a", "--arp", help="Query ARP protocol",action="store_true", dest="ARP")
parser.add_argument("-d", "--dns", help="Query DNS protocol",action="store_true", dest="DNS")
parser.add_argument("-t", "--tcp", help="Query TCP protocol",action="store_true", dest="TCP")
parser.add_argument("-w", "--http", help="Query HTTP protocol",action="store_true", dest="HTTP")
parser.add_argument("-s", "--tls", help="Query TLS protocol",action="store_true", dest="TLS")
args = parser.parse_args()

packets = rdpcap(args.pcap)

#iterate through packets
for packet in packets:
    process_pcap(packet)
    
