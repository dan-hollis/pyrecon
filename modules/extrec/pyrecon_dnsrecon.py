#!/usr/bin/python3
import os
import json
import subprocess
import socket # used to validate and sort ipv4 and ipv6 addresses

def ip_sort_key(ip):
	"""
	Key used in sorting ipv4 and ipv6 addresses
	"""
	try:
		return socket.inet_pton(socket.AF_INET6, ip)
	except socket.error:
		return socket.inet_pton(socket.AF_INET, ip)

def pyrecon_dnsrecon(target_domain_file, dnsrecon_configs):
	"""
	Parses dnsrecon data and returns several lists:
	Hostname of all nameservers (ns_hosts)
	All hostnames from cname, a, and mx records (subdomains)
	All ipv4 addresses (ipv4 is the sorted list)
	All ipv6 addresses (ipv6 is the sorted list)
	All txt records (txtrecord_strings)
	Anything else not matching the above (other_records)
	"""
	dnsrecon_directory = dnsrecon_configs["dnsrecon_directory"]
	dnsrecon_output = os.path.join(dnsrecon_directory, 'dnsrecon')
	with open(target_domain_file, 'r') as read_domains:
		domain_list = read_domains.read().splitlines()

	for host in domain_list:
		dnsrecon_json_output = os.path.abspath("{0}_{1}.json".format(dnsrecon_output, host))
		dnsrecon_csv_output = os.path.abspath("{0}_{1}.csv".format(dnsrecon_output, host))
		dnsrecon_ns_hosts_output = os.path.abspath("{0}_nameservers_{1}.txt".format(dnsrecon_output, host))
		dnsrecon_subdomains_output = os.path.abspath("{0}_subdomains_{1}.txt".format(dnsrecon_output, host))
		dnsrecon_ipv4_output = os.path.abspath("{0}_ipv4_{1}.txt".format(dnsrecon_output, host))
		dnsrecon_ipv6_output = os.path.abspath("{0}_ipv6_{1}.txt".format(dnsrecon_output, host))
		dnsrecon_txtrecords_output = os.path.abspath("{0}_txt_records_{1}.json".format(dnsrecon_output, host))
		dnsrecon_other_output = os.path.abspath("{0}_other_{1}.json".format(dnsrecon_output, host))
		subprocess.call(["dnsrecon", "-t", "std", "-a", "-k", "-j", dnsrecon_json_output, "-c", dnsrecon_csv_output, "-d", host])
		with open(dnsrecon_json_output, 'r') as read_dnsrecon_output:
			dnsrecon_json = json.load(read_dnsrecon_output)
		ns_hosts = [] # variable to hold ns record ipv4 addresses
		subdomains = []
		ipv4_unsorted = [] # variable to hold any other record ipv4 addresses
		ipv6_unsorted = [] # variable to hold any other record ipv4 addresses
		txtrecord_strings = [] # variable to hold txt record strings
		other_records = [] # currently unhandled records
		for record in dnsrecon_json:
			try:
				record_type = record["type"].upper()
				if record_type == "TXT" or record_type == "INFO":
					string = record["strings"]
					if record not in txtrecord_strings:
						txtrecord_strings.append(record)
				else:
					try:
						ip = record["address"]
						try:
							check_valid_address = socket.inet_pton(socket.AF_INET, ip) # check if valid ipv4 address
							if ip not in ipv4_unsorted:
								ipv4_unsorted.append(ip)
						except socket.error:
							try:
								check_valid_address = socket.inet_pton(socket.AF_INET6, ip) # check if valid ipv6 address
								if ip not in ipv6_unsorted:
									ipv6_unsorted.append(ip)
							except:
								pass
					except KeyError:
						# Skip over any non txt or info record without an ip address field
						pass
					finally:
						if record_type == "NS":
							try:
								ns_host = record["target"]
								if ns_host not in ns_hosts:
									ns_hosts.append(ns_host)
							except KeyError:
								pass
						if record_type == "CNAME" or record_type == "A" or record_type == "MX":
							try:
								subdomain = record["name"]
								if subdomain not in subdomains:
									subdomains.append(subdomain)
							except KeyError:
								pass
			except KeyError:
				# Records without a type get added with other records
				other_records.append(record)
		# Begin writing to files
		if ipv4_unsorted:
			ipv4 = sorted(ipv4_unsorted, key=ip_sort_key)
			with open(dnsrecon_ipv4_output, 'w') as dnsrecon_ipv4_output:
				for ip in ipv4:
					dnsrecon_ipv4_output.write('{0}\n'.format(ip))
		if ipv6_unsorted:
			ipv6 = sorted(ipv6_unsorted, key=ip_sort_key)
			with open(dnsrecon_ipv6_output, 'w') as dnsrecon_ipv6_output:
				for ip in ipv6:
					dnsrecon_ipv6_output.write('{0}\n'.format(ip))
		if ns_hosts:
			with open(dnsrecon_ns_hosts_output, 'w') as dnsrecon_ns_hosts_output:
				for host in ns_hosts:
					dnsrecon_ns_hosts_output.write('{0}\n'.format(host))
		if subdomains:
			with open(dnsrecon_subdomains_output, 'w') as dnsrecon_subdomains_output:
				for subdomain in subdomains:
					dnsrecon_subdomains_output.write('{0}\n'.format(subdomain))
		if txtrecord_strings:
			with open(dnsrecon_txtrecords_output, 'w') as dnsrecon_txtrecords_output:
				json.dump(txtrecord_strings, dnsrecon_txtrecords_output, indent=4)
		if other_records:
			with open(dnsrecon_other_output, 'w') as dnsrecon_other_output:
				json.dump(other_records, dnsrecon_other_output, indent=4)
