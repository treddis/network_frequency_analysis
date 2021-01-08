#!/usr/bin/env python3
#! -*- coding: utf-8 -*-

import scapy.all as scapy
import argparse
import pdb
from sys import argv

parser = argparse.ArgumentParser(description='sniffer for frequence analyze of traffic')
parser.add_argument('mode', choices=['counting'],
	help='mode of working: counting - estimation of packets')

if len(argv) == 1:
	parser.print_help()
	exit(1)
opts = parser.parse_args()
ether_layer = {
	'dst': {},
	'src': {},
	'type': {}
}
ip_layer = {
	'options': {},
	'version': {},
	'ihl': {},
	'tos': {},
	'dsf': {},
	'len': {},
	'id': {},
	'flags': {},
	'frag': {},
	'ttl': {},
	'proto': {},
	'chksum': {},
	'src': {},
	'dst': {}
}
tcp_layer = {
	'sport': {},
	'dport': {},
	'seq': {},
	'ack': {},
	'dataofs': {},
	'reserved': {},
	'flags': {},
	'window': {},
	'chksum': {},
	'urgptr': {},
	'options': {}
}
TCP = scapy.TCP
UDP = scapy.UDP
Ether = scapy.Ether
IP = scapy.IP

def print_dict_pretty(dic, tabnum=0):
	for key in dic.keys():
		if type(dic[key]) == dict:
			print('\t' * tabnum + key + ':')
			print_dict_pretty(dic[key], tabnum + 1)
		else:
			print('\t' * tabnum, end='')
			print(f"{key} : {dic[key]}")

def main():
	global ether_layer

	pkts = scapy.sniff()

	if opts.mode == 'counting':
		for pkt in pkts:
			if pkt.haslayer(Ether):
				if pkt[Ether].fields['dst'] not in ether_layer['dst']:
					ether_layer['dst'][pkt[Ether].fields['dst']] = 0
				else:
					ether_layer['dst'][pkt[Ether].fields['dst']] += 1
				if pkt[Ether].fields['src'] not in ether_layer['src']:
					ether_layer['src'][pkt[Ether].fields['src']] = 0
				else:
					ether_layer['src'][pkt[Ether].fields['src']] += 1
				if pkt[Ether].fields['type'] not in ether_layer['type']:
					ether_layer['type'][pkt[Ether].fields['type']] = 0
				else:
					ether_layer['type'][pkt[Ether].fields['type']] += 1

			# pdb.set_trace()
			if pkt.haslayer(IP):
				for key in pkt[IP].fields.keys():
					if type(pkt[IP].fields[key]) is list:
						pkt[IP].fields[key] = tuple(pkt[IP].fields[key])
					if pkt[IP].fields[key] not in ip_layer[key]:
						ip_layer[key][pkt[IP].fields[key]] = 1
					else:
						ip_layer[key][pkt[IP].fields[key]] += 1
			if pkt.haslayer(TCP):
				for key in pkt[TCP].fields.keys():
					if type(pkt[TCP].fields[key]) is list:
						pkt[TCP].fields[key] = tuple(pkt[TCP].fields[key])
					if pkt[TCP].fields[key] not in tcp_layer[key]:
						tcp_layer[key][pkt[TCP].fields[key]] = 1
					else:
						tcp_layer[key][pkt[TCP].fields[key]] += 1


	print('[+] Result of working: Ethernet II')
	print_dict_pretty(ether_layer)
	print('\n[+] Result of working: IP')
	print_dict_pretty(ip_layer)
	print('\n[+] Result of working: TCP')
	print_dict_pretty(tcp_layer)

if __name__ == '__main__':
	main()