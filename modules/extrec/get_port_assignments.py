#!/usr/bin/python3
import os
import requests
from bs4 import BeautifulSoup
from modules.colors import colors

def get_port_assignments(adminsub_search_configs):
	"""
		Search adminsub.net for info on discovered ports
		Useful for looking up reported malicious software, etc. on open ports
	"""
	adminsub_search_input = os.path.abspath(adminsub_search_configs["adminsub_search_input"])
	adminsub_search_directory = adminsub_search_configs["adminsub_search_directory"]
	adminsub_search_output = os.path.join(adminsub_search_directory, 'adminsub_report.html')
	with open(adminsub_search_input) as adminsub_search_input:
		ports = sorted(set(map(int, (adminsub_search_input.read().splitlines()))))
	print(colors.YELLOW + '[*] Starting adminsub.net search for {0} ports...'.format(len(ports)) + colors.RESET)
	for port in ports:
		request = requests.get('http://www.adminsub.net/tcp-udp-port-finder/{0}'.format(port))
		soup = BeautifulSoup(request.text, 'html.parser')
		stylesheet = soup.find('link', rel='stylesheet')
		table = soup.find('div', class_='bl558_m10')
		
		total_records = 0
		records_found_divs = soup.find_all('div', class_='bl558_header0 hcenter')
		for records_found in records_found_divs:
			# str to get records found at index 7 then to int for adding to total records
			num_records = int(str(records_found.find('span'))[7])
			total_records += num_records
		
		unassigned = 0
		details_divs = soup.find_all('div', class_='bl558_s')
		for details in details_divs:
			if 'Unassigned' in details:
				unassigned += 1
		
		with open(adminsub_search_output, 'a') as report_file:
			"""
			Create collapsible buttons containing adminsub.net results table HTML
			"""
			report_file.write('<div data-role=\"main\" class=\"ui-content\">\n')
			report_file.write('<div data-role=\"collapsible\">\n')
			# adminsub.net results table HTML
			# 2 total records with 2 unassigned means adminsub.net and IANA have no assignments for that port
			if total_records == 2 and unassigned == 2:
				print(colors.YELLOW + '[*] ' + colors.RESET + 'Port {0} is unassigned...'.format(port))
				report_file.write('<h3>Port {0} (Unassigned)</h3>\n{1}\n</div>\n</div>\n'.format(port, table))
			else:
				print(colors.GREEN + '[+] ' + colors.RESET + '{0} records found for port {1}...'.format(total_records - unassigned, port))
				report_file.write('<h3>Port {0}</h3>\n{1}\n</div>\n</div>\n'.format(port, table))
	
	# Rewrite report.html with necessary CSS and JavaScript
	# Might be a more efficient way to go about this
	# This works by reading the HTML of adminsub.net tables into a variable
	# The necessary CSS and JavaScript are then written over the old report.html and the adminsub.net HTML variable is appended
	with open(adminsub_search_output, 'r') as report_file_old:
		save_contents = report_file_old.read()
	with open(adminsub_search_output, 'w') as report_file_new:
		report_file_new.write('<!DOCTYPE html>\n<html>\n<head>\n')
		# CSS
		report_file_new.write('<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n')
		report_file_new.write('<link rel=\"stylesheet\" href=\"https://code.jquery.com/mobile/1.4.5/jquery.mobile-1.4.5.min.css\">\n')
		# adminsub.net CSS
		report_file_new.write('{0}\n'.format(stylesheet))
		# JavaScript
		report_file_new.write('<script src=\"https://code.jquery.com/jquery-1.11.3.min.js\"></script>\n')
		report_file_new.write('<script src=\"https://code.jquery.com/mobile/1.4.5/jquery.mobile-1.4.5.min.js\"></script>\n</head>\n<body>\n')
	with open(adminsub_search_output, 'a') as report_file_new:
		report_file_new.write(save_contents)
		report_file_new.write('</body>\n</html>')
	print(colors.GREEN + '[+] Done. adminsub.net report saved to {0}\n'.format(adminsub_search_output) + colors.RESET)	