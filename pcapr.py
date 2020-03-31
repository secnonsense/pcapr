#!/usr/local/bin/python

from scapy.all import *
import argparse
response_payload_len = 0

def process_pcap(request):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    global response_sequence_number
    global response_acknowledgement_number
    global response_timestamp
    global response_payload_len

    if request.haslayer(Ether):
        print "Ether Src: " + request[Ether].src + " - Ether Dst: " + request[Ether].dst

    if request.haslayer(IP):
        print "IP Src: " + request[IP].src + " - IP Dst: " + request[IP].dst + " - IP ID: " + str(request[IP].id)

    if request.haslayer(UDP):
        print "UDP - Source Port: " + str(request[UDP].sport) + "  Destination Port: " + str(request[UDP].dport)   

    if request.haslayer(TCP):
        response_sequence_number = request[TCP].seq
        response_acknowledgement_number = request[TCP].ack
        response_timestamp = request[TCP].time
        response_payload_len += len(request[TCP].payload)
        
        print "TCP - Source Port: " + str(request[TCP].sport) + "  Destination Port: " + str(request[TCP].dport)
        print "Response seq: " + str(response_sequence_number) + " ack: " + \
              str(response_acknowledgement_number) + " timestamp: " + str(response_timestamp) + " len: " + \
              str(len(request[TCP].payload)) 
        F = request['TCP'].flags    
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
    
