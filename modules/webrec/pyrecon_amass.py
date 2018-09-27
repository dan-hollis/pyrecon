#!/usr/bin/bash
import os
import json
import subprocess
from modules.colors import colors

def pyrecon_amass(target_domain_file, subdomains_all_file, amass_configs):
	amass_directory = os.path.abspath(amass_configs["amass_directory"])
	amass_json_output = os.path.join(os.path.abspath(amass_directory), "amass.json")
	amass_txt_output = os.path.join(os.path.abspath(amass_directory), "amass.txt")
	amass_bruteforce = amass_configs["bruteforce_enabled"]
	with open(target_domain_file, 'r') as target_domain_file_read:
		target_domain_list = target_domain_file_read.read().splitlines()
	if len(target_domain_list) > 1:
		print('{1}[*] Running amass against {2} domains{0}:'.format(colors.RESET, colors.YELLOW, len(target_domain_list)))
		for domain in target_domain_list[:-1]:
			print('\t{0}\n'.format(domain))
		print('\t{0}'.format(target_domain_list[-1]))
	else:
		print('{1}[*] Running amass against {2} domain{0}:'.format(colors.RESET, colors.YELLOW, len(target_domain_list)))
		print('\t{0}'.format(target_domain_list[0]))
	if amass_bruteforce:
		subprocess.call(["amass", "-brute", "-df", target_domain_file, "-json", amass_json_output, "-o", amass_txt_output])
	else:
		subprocess.call(["amass", "-df", target_domain_file, "-json", amass_json_output, "-o", amass_txt_output])
	
	# Read amass broken json output as list. It's incorrectly formatted for loading into python
	# Convert strings to dictionary objects using json.loads and store in fixed_json list
	fixed_json = []
	with open(amass_json_output, 'r') as read_broken_json:
		amass_broken_json = read_broken_json.read().splitlines()
		for json_dict in amass_broken_json:
			fixed_json.append(json.loads(json_dict))
	# Write over old amass json with fixed amass json
	with open(amass_json_output, 'w') as write_fixed_json:
		json.dump(fixed_json, write_fixed_json, indent=4)
	# Load fixed json
	with open(amass_json_output, 'r') as read_json:
		amass_json = json.load(read_json)

	try:
		with open(subdomains_all_file, 'r') as read_subdomains:
			subdomains = read_subdomains.read().splitlines()
	except FileNotFoundError:
		subdomains = []
	for item in amass_json:
		subdomain = item["name"]
		if subdomain not in subdomains:
			subdomains.append(subdomain)
	with open(subdomains_all_file, 'a') as write_subdomains:
		for subdomain in subdomains:
			write_subdomains.write('{0}\n'.format(subdomain))
	print('{1}[+] Done. Amass outputs saved to {2}{0}'.format(colors.RESET, colors.GREEN, amass_directory) + colors.RESET)
