#!/usr/bin/python3
import os
import json
import time
import whois
from ipwhois import IPWhois
import warnings
from modules.colors import colors

def pyrecon_ip_whois(target_subnet_file, target_domain_file, ip_whois_configs):
	"""
	Create a list of subnets based off of whois IP lookups (cidrs)
	"""
	ipwhois_input = ip_whois_configs["ip_whois_input"]
	ipwhois_directory = ip_whois_configs["ip_whois_directory"]
	ipwhois_output = os.join(ipwhois_directory, 'ipwhois')
	with open(target_domain_file, 'r') as read_domains:
		domain_list = read_domains.read().splitlines()
	print('{0}\n[+] Finding subnets...{1}'.format(colors.GREEN, colors.RESET))
	for host in domain_list:
		ipwhois_cidr_output = os.path.abspath("{0}_cidrs_{1}.txt".format(ipwhois_output, host))
		ipwhois_json_output = os.path.abspath("{0}_{1}.json".format(ipwhois_output, host))
		ipv4_file = os.path.abspath("{0}_ipv4_{1}.txt".format(ipwhois_input, host))
		with open(ipv4_file, 'r') as read_ipv4:
			ip_list = read_ipv4.read().splitlines()
		cidrs = []
		for ip in ip_list:
			with warnings.catch_warnings():
				warnings.filterwarnings("ignore", category=UserWarning)
				whois_object = IPWhois(ip) 
				whois_data = whois_object.lookup_rdap()
			try:
				asn = whois_data["asn"]
			except KeyError:
				asn = "Not Found"
			try:
				asn_name = whois_data["asn_description"]
			except KeyError:
				asn_name = "Not Found"
			try:
				cidr = whois_data["network"]["cidr"]
				if ',' in cidr: # Have gotten multiple cidrs returned from whois seperated by commas
					got_cidr_list = cidr.split()
					for broken_cidr in got_cidr_list:
						fixed_cidr = broken_cidr.replace(',', '')
						if fixed_cidr not in cidrs:
							cidrs.append(fixed_cidr)
						print('{4}IP{5}: {0:<20.15} {4}CIDR{5}: {1:<20.18} {4}ASN{5}: {2:<10.10} '
								'{4}NAME{5}: {3:<15.100}'.format(ip, fixed_cidr, asn, asn_name, colors.YELLOW, colors.RESET))
					continue
			except KeyError:
				try:
					cidr = whois_data["asn_cidr"]
					if ',' in cidr: # Have gotten multiple cidrs returned from whois seperated by commas
						got_cidr_list = cidr.split()
						for broken_cidr in got_cidr_list:
							fixed_cidr = broken_cidr.replace(',', '')
							if fixed_cidr not in cidrs:
								cidrs.append(fixed_cidr)
							print('{4}IP{5}: {0:<20.15} {4}CIDR{5}: {1:<20.18} {4}ASN{5}: {2:<10.10} '
									'{4}NAME{5}: {3:<15.100}'.format(ip, fixed_cidr, asn, asn_name, colors.YELLOW, colors.RESET))
						continue
				except:
					cidr = None
			if cidr not in cidrs and cidr is not None:
				print('{4}IP{5}: {0:<20.15} {4}CIDR{5}: {1:<20.18} {4}ASN{5}: {2:<10.10} '
						'{4}NAME{5}: {3:<15.100}'.format(ip, cidr, asn, asn_name, colors.YELLOW, colors.RESET))
				cidrs.append(cidr)
			time.sleep(0.5)
		with open(ipwhois_cidr_output, 'w') as write_output:
			for cidr in cidrs:
				write_output.write('{0}\n'.format(cidr))
	print('{0}[+] Done.\n{1}'.format(colors.GREEN, colors.RESET))