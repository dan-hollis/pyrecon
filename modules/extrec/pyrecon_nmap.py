#!/usr/bin/bash
import os
import subprocess
from modules.colors import colors

def pyrecon_nmap(nmap_directory, output_directory):
	target_subnet_file = os.path.join(output_directory, 'subnets.txt')
	nmap_input = os.path.join(output_directory, 'external_recon/portscan/open_ports.txt')
	nmap_output = os.path.join(nmap_directory, 'nmap')
	if not os.path.isfile(nmap_input):
		return
	if os.path.isfile(os.path.join(nmap_directory, 'nmap.csv')) and os.stat(os.path.join(nmap_directory, 'nmap.csv')).st_size > 0:
		raise FileExistsError
	with open(target_subnet_file) as target_subnet_file_readlines:
		cidrs = target_subnet_file_readlines.readlines()
		number_cidr_nets = len(cidrs)
	with open(nmap_input, 'r') as nmap_ports_file:
		# Get port list and strip last comma
		nmap_ports = nmap_ports_file.read().replace('\n', ',')[:-1]
	if number_cidr_nets > 1:
		print(colors.YELLOW + '[*] Running nmap on {0} hosts/CIDR nets:'.format(number_cidr_nets) + colors.RESET)
		for cidr in cidrs[:-1]:
			print('\t{0}'.format(cidr.rstrip('\n')))
		print('\t{0}\n'.format(cidrs[-1].rstrip('\n')))
		subprocess.call(["nmap", "-sS", "-Pn", "-v", "-A", "-p", nmap_ports, "-oA", nmap_output,  "-iL", target_subnet_file])
	elif number_cidr_nets == 1:
		with open(target_subnet_file) as target_subnet_file_read:
			cidr = target_subnet_file_read.read()
		print(colors.YELLOW + '[*] Running nmap on {0} host/CIDR net:'.format(number_cidr_nets) + colors.RESET)
		print('\t{0}'.format(cidr))
		subprocess.call(["nmap", "-sS", "-Pn", "-v", "-A", "-p", nmap_ports, "-oA", nmap_output,  "-iL", target_subnet_file])

	# Convert nmap.xml to nmap.html with xsltproc
	nmap_xml_output = os.path.join(os.path.abspath(nmap_directory), 'nmap.xml')
	nmap_html_output = os.path.join(os.path.abspath(nmap_directory), 'nmap.html')
	subprocess.call(["xsltproc", nmap_xml_output, "-o", nmap_html_output])

	"""
		Convert nmap.gnmap output to nmap.csv for spreadsheet imports:
			This is done by making a system call to nmaptocsv which is placed in the path after setup.sh
			nmaptocsv.py author's github: 
					https://github.com/maaaaz/nmaptocsv
	"""
	nmap_greppable_output = os.path.join(nmap_directory, 'nmap.gnmap')
	nmaptocsv_output = os.path.join(nmap_directory, 'nmap.csv')
	subprocess.call(["nmaptocsv", "-i", nmap_greppable_output, "-o", nmaptocsv_output, "-f", "ip-fqdn-os-protocol-port-service", "-d", ","])

	print(colors.GREEN + '\n[+] Done. Nmap outputs saved to {0}\n'.format(nmap_directory) + colors.RESET)
