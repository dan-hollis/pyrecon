#!/usr/bin/python3
import os
import json
import sys
import subprocess
from modules.lib.colors import colors

def pyrecon_masscan(masscan_directory, output_directory, masscan_rate):
	target_subnet_file = os.path.join(output_directory, 'subnets.txt')
	masscan_json = os.path.join(masscan_directory, 'masscan.json')
	if not os.path.isfile(target_subnet_file) or os.stat(target_subnet_file).st_size == 0:
		raise FileNotFoundError
	if os.path.isfile(masscan_json) and os.stat(masscan_json).st_size > 0:
		raise FileExistsError
	with open(target_subnet_file, 'r') as target_subnet_file_readlines:
		cidrs = target_subnet_file_readlines.readlines()
		number_cidr_nets = len(cidrs)
	if number_cidr_nets > 1:
		print('{1}[*] Running masscan on {2} hosts/CIDR nets{0}:'.format(colors.RESET, colors.YELLOW, number_cidr_nets))
		for cidr in cidrs:
			print('\t{0}'.format(cidr.rstrip('\n')))
		print('{1}[*] Rate set to{0}:'.format(colors.RESET, colors.YELLOW))
		print('\t{0}'.format(masscan_rate))
		subprocess.call(["masscan", "-oJ" , masscan_json, "--rate", str(masscan_rate), "-iL", target_subnet_file, "-p1-65535", "--interactive"])
	elif number_cidr_nets == 1:
		with open(target_subnet_file) as target_subnet_file_read:
			cidr = target_subnet_file_read.read()
		print('{1}[*] Running masscan on {2} hosts/CIDR nets{0}:'.format(colors.RESET, colors.YELLOW, number_cidr_nets))
		print('\t{0}'.format(cidr))
		print(colors.YELLOW + '[*] Rate set to:' + colors.RESET)
		print('\t{0}'.format(masscan_rate))
		subprocess.call(["masscan", "-oJ" , masscan_json, "--rate", str(masscan_rate), "-iL", target_subnet_file, "-p1-65535", "--interactive"])
	print('\n{1}[+] Done. Masscan JSON output saved to {2}{0}'.format(colors.RESET, colors.GREEN, masscan_json) + colors.RESET)
	if os.stat(masscan_json).st_size != 0:
		with open(masscan_json, 'r') as broken_json:
			"""
			masscan json output contains a comma in the last value
			this causes Python's json to break when attempting to load json from the file
			this can be fixed by finding the last value and removing the comma with string manipulation
			"""
			# Convert masscan JSON output to a list
			broken_json_lines = list(broken_json)
			# Broken line is the second to last value
			last_value = broken_json_lines[-2]
			# Get index value of last occurence of a comma in broken line
			last_comma_index = last_value.rfind(',')
			# Create string to hold value of broken line without comma
			new_last_value = last_value[:last_comma_index] + last_value[last_comma_index + 1:]
		# Write everything except the last 2 lines from old json to new json file
		with open(masscan_json, 'w') as old_json:
			old_json.writelines(broken_json_lines[:-2])
		# Append new json file with the fixed last value and closing bracket
		with open(masscan_json, 'a') as new_json:
			new_json.write('{0}]\n'.format(new_last_value))
		
		with open(masscan_json, 'r') as masscan_json:
			masscan_json = json.load(masscan_json)
		
		open_port_list = []
		for item in range(len(masscan_json)):
			port = masscan_json[item]["ports"][0]["port"]
			if port not in open_port_list:
				open_port_list.append(port)
		# create a list of open ports with new line characters after each port
		# this is used to create a text file of line seperated ports
		open_port_list = [str(port) + "\n" for port in sorted(open_port_list)]
	
		with open(os.path.join(output_directory, 'external_recon/portscan/open_ports.txt'), 'a') as open_ports_file:
			# create file with a new line seperated list of ports
			open_ports_file.writelines(open_port_list)
		print('{1}[+] Line seperated list of open ports saved to {2}{0}\n'.format(colors.RESET, colors.GREEN, open_ports_file.name) + colors.RESET)
	else:
		print('{1}[!] Masscan found no open ports. Skipping Nmap...{0}\n'.format(colors.RESET, colors.RED))

"""
masscan -oJ <OUTFILE> -p1-65535 --rate <rate> -iL <ALL_LIVE_IPS_FILE>
-oJ <OUTFILE> 
Sets output format to JSON
-iL <ALL_LIVE_IPS_FILE>
Takes new line seperated file as input
"""