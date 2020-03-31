#!/usr/local/bin/python

from scapy.all import *
import argparse
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

    if pcap.haslayer(Ether):
        print "Ether Src: " + pcap[Ether].src + " - Ether Dst: " + pcap[Ether].dst

    if pcap.haslayer(IP):
        print "IP Src: " + pcap[IP].src + " - IP Dst: " + pcap[IP].dst + " - IP ID: " + str(pcap[IP].id)

    if pcap.haslayer(UDP):
        print "UDP - Source Port: " + str(pcap[UDP].sport) + "  Destination Port: " + str(pcap[UDP].dport)   

    if pcap.haslayer(TCP):
        sequence_number = pcap[TCP].seq
        acknowledgement_number = pcap[TCP].ack
        timestamp = pcap[TCP].time
        payload_len += len(pcap[TCP].payload)
        
        print "TCP - Source Port: " + str(pcap[TCP].sport) + "  Destination Port: " + str(pcap[TCP].dport)
        print "Response seq: " + str(sequence_number) + " ack: " + \
              str(acknowledgement_number) + " timestamp: " + str(timestamp) + " len: " + \
              str(len(pcap[TCP].payload)) 
        F = pcap['TCP'].flags    
        print "Flags: ",
        if F & FIN:
            print "FIN",
        if F & SYN:
            print "SYN",
        if F & RST:
            print "RST",
        if F & ACK:
            print "ACK",
        if F & PSH:
            print "PSH",
        if F & URG:
            print "URG",        
        if F & ECE:
            print "ECE",
        if F & CWR:
            print "CWR", 
        print "\r\n"        
    print "-----------\r\n"    

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--read", help="read pcapfile",action="store", dest="pcap", required=True)
args = parser.parse_args()

packets = rdpcap(args.pcap)

#iterate through packets
for packet in packets:
    process_pcap(packet)
    
