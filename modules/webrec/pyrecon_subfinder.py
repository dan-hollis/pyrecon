#!/usr/bin/bash
import os
import json
import subprocess
from modules.lib.colors import colors

def pyrecon_subfinder(target_domain_file, subdomains_all_file, subfinder_configs):
	subfinder_directory = os.path.abspath(subfinder_configs["subfinder_directory"])
	subfinder_output = os.path.join(subfinder_directory, "subfinder.json")
	subfinder_bruteforce = subfinder_configs["bruteforce_enabled"]
	subfinder_wordlist = subfinder_configs["wordlist"]
	subfinder_threads = subfinder_configs["threads"]
	with open(target_domain_file, 'r') as target_domain_file_read:
		target_domain_list = target_domain_file_read.read().splitlines()
	if len(target_domain_list) > 1:
		print(colors.YELLOW + '[*] Running subfinder against {0} domains:'.format(len(target_domain_list)) + colors.RESET)
		for domain in target_domain_list[:-1]:
			print('\t{0}\n'.format(domain))
		print('\t{0}'.format(target_domain_list[-1]))
	else:
		print(colors.YELLOW + '[*] Running subfinder against {0} domain:'.format(len(target_domain_list)) + colors.RESET)
		print('\t{0}\n'.format(target_domain_list[0]))
	if subfinder_bruteforce:
		subprocess.call(["subfinder", "-dL", target_domain_file, "-oJ", "-o", subfinder_output, "-t", subfinder_threads, 
							"-b", "-w", subfinder_wordlist])
	else:
		subprocess.call(["subfinder", "-dL", target_domain_file, "-oJ", "-o", subfinder_output, "-t", subfinder_threads])

	with open(subfinder_output, 'r') as read_subfinder_json:
		subfinder_json = json.load(read_subfinder_json)
	try:
		with open(subdomains_all_file, 'r') as read_subdomains:
			subdomains = read_subdomains.read().splitlines()
	except FileNotFoundError:
		subdomains = []
	for subdomain in subfinder_json:
		if subdomain not in subdomains:
			subdomains.append(subdomain)
	with open(subdomains_all_file, 'a') as write_subdomains:
		for subdomain in subdomains:
			write_subdomains.write('{0}\n'.format(subdomain))
	print(colors.GREEN + '[+] Done. Subfinder JSON output saved to {0}\n'.format(subfinder_output) + colors.RESET)
