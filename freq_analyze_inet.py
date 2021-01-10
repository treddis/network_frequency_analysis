#!/usr/bin/env python3
#! -*- coding: utf-8 -*-

# Copyright © 2021 Thomas Reddison. All rights reserved.

import scapy
import scapy.all
import argparse
import pdb
import pandas
from sys import argv, stderr
from json import dumps
from time import sleep

LAYERS = ['link', 'internet', 'transport', 'application']
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
udp_layer = {
	'sport': {},
	'dport': {},
	'len': {},
	'chksum': {}
}
Ether = scapy.all.Ether
IP = scapy.all.IP
TCP = scapy.all.TCP
UDP = scapy.all.UDP

def print_report(out_format, data):
	if out_format == 'pretty':
		print_dict_pretty(data)
	elif out_format == 'json':
		print(dumps(data))
	elif out_format == 'csv':
		# pdb.set_trace()
		pandas_data = pandas.read_json(dumps(data))
		print(pandas_data.to_csv())
	# elif out_format == 'xml':
	# 	pass

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

	if timer:
		# sniffer = scapy.all.AsyncSniffer()
		# sniffer.start()
		# sleep(timer)
		# pkts = sniffer.stop()
		pkts = scapy.all.sniff(timeout=timer)
		# del sniffer
	else:
		pkts = scapy.all.sniff()

	# if opts.mode == 'counting':
	for pkt in pkts:
		if pkt.haslayer(Ether) and 'link' in layers:
			for key in pkt[Ether].fields.keys():
				if pkt[Ether].fields[key] not in ether_layer[key]:
					ether_layer[key][pkt[Ether].fields[key]] = 1
				else:
					ether_layer[key][pkt[Ether].fields[key]] += 1

		if pkt.haslayer(IP) and 'internet' in layers:
			for key in pkt[IP].fields.keys():
				if type(pkt[IP].fields[key]) is list:						# Fix TypeError: unhashable type: 'list'
					pkt[IP].fields[key] = str(pkt[IP].fields[key])
				elif type(pkt[IP].fields[key]) is scapy.fields.FlagValue:   # Fix TypeError: FlagValue for dumps()
					pkt[IP].fields[key] = str(pkt[IP].fields[key])
				if pkt[IP].fields[key] not in ip_layer[key]:
					ip_layer[key][pkt[IP].fields[key]] = 1
				else:
					ip_layer[key][pkt[IP].fields[key]] += 1
		if pkt.haslayer(TCP) and 'transport' in layers:
			for key in pkt[TCP].fields.keys():
				if type(pkt[TCP].fields[key]) is list:						# Fix TypeError: unhashable type: 'list'
					pkt[TCP].fields[key] = str(pkt[TCP].fields[key])
				elif type(pkt[TCP].fields[key]) is scapy.fields.FlagValue:  # Fix TypeError: FlagValue for dumps()
					pkt[TCP].fields[key] = str(pkt[TCP].fields[key])
				if pkt[TCP].fields[key] not in tcp_layer[key]:
					tcp_layer[key][pkt[TCP].fields[key]] = 1
				else:
					tcp_layer[key][pkt[TCP].fields[key]] += 1
		if pkt.haslayer(UDP) and 'transport' in layers:
				for key in pkt[UDP].fields.keys():
					if type(pkt[UDP].fields[key]) is list:						# Fix TypeError: unhashable type: 'list'
						pkt[UDP].fields[key] = str(pkt[UDP].fields[key])
					elif type(pkt[UDP].fields[key]) is scapy.fields.FlagValue:  # Fix TypeError: FlagValue for dumps()
						pkt[UDP].fields[key] = str(pkt[UDP].fields[key])
					if pkt[UDP].fields[key] not in udp_layer[key]:
						udp_layer[key][pkt[UDP].fields[key]] = 1
					else:
						udp_layer[key][pkt[UDP].fields[key]] += 1			

	# pdb.set_trace()
	if 'link' in layers:
		print('[+] Report: Link layer', file=stderr)
		if output == 'json':
			print_report('json', ether_layer)
		elif output == 'csv':
			print_report('csv', ether_layer)
		else:
			print_report('pretty', ether_layer)
	if 'internet' in layers:
		print('\n[+] Report: Internet layer', file=stderr)
		if output == 'json':
			print_report('json', ip_layer)
		elif output == 'csv':
			print_report('csv', ip_layer)
		else:
			print_report('pretty', ip_layer)
	if 'transport' in layers:
		print('\n[+] Report: Transport layer', file=stderr)
		trans_layer = {
			'tcp': tcp_layer,
			'udp': udp_layer}
		if output == 'json':
			print_report('json', trans_layer)
		elif output == 'csv':
			print_report('csv', trans_layer)
		else:
			print_report('pretty', trans_layer)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='sniffer for frequence analyze of traffic')
	parser.add_argument('-o', '--output', choices=['json', 'csv'],
		help='output format of report')
	parser.add_argument('-l', '--layer', type=str,
		metavar='{link,internet,transport,application}', help='choose layer for analyze and forging report')
	parser.add_argument('-t', '--timer', type=int,
		help='set timer in seconds to stop capturing after expiration')
	parser.add_argument('mode', choices=['counting'],
		help='mode of working: counting - estimation of packets')

	if len(argv) == 1:
		parser.print_help()
		exit(1)

	opts = parser.parse_args()
	layers = opts.layer.split(',')
	if len([x for x in layers if x not in LAYERS]):
		parser.error('Invalid parameter "--layer"')
	# pdb.set_trace()
	timer = opts.timer
	output = opts.output if opts.output else None

	main()
