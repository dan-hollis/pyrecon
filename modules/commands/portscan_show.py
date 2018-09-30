#!/usr/bin/python3

import sqlite3

from beautifultable import BeautifulTable

from modules.lib import ip_validator
from modules.lib.colors import colors
from modules.lib.errors import ArgumentError

def portscan_show(db_file, args):
	"""Parses nmap data to create structured data and prints to terminal."""
	args = [arg.lower() for arg in args.split()]
	table = BeautifulTable()
	conn = sqlite3.connect(db_file)
	cur = conn.cursor()
	if len(args) == 1 and not args[0][0].isdigit():
		# If the first index isn't a digit, it's not an IP
		# Must be webservers or ArgumentError is raised
		table.column_headers = ['IP', 'FQDN', 'OS', 'PROTOCOL', 'PORT', 'SERVICE']
		if args[0] == 'webservers':
			try:
				ports = ['80','443','8080','8443']
				cur.execute('SELECT * from nmap_data WHERE port IN (?,?,?,?)', ports)
				results = cur.fetchall()
			except sqlite3.OperationalError:
				raise sqlite3.OperationalError
			for result in results:
				table.append_row([result[0], result[1], result[2], result[3], result[4], result[5]])
			conn.close()
			print(table)
			return
		conn.close()
		raise ArgumentError('{1}[!] Invalid argument given to {0}show.'.format(colors.RESET, colors.RED))
	if len(args) == 2 or len(args) == 1:
		# If the previous check failed, it has to be an IP or ArgumentError is raised
		# If it's a valid IP, return a table with the IP and selected port info
		if ip_validator.is_valid_ipv4(args[0]) or ip_validator.is_valid_ipv6(args[0]):
			table.column_headers = ['IP', 'FQDN', 'OS', 'PROTOCOL', 'PORT', 'SERVICE']
			ip_and_ports = [args[0]]
			if len(args) == 2:
				if args[1].lower() == 'webservers':
					ip_and_ports.extend(['80','443','8080','8443'])
				else:
					for port in args[1].split(','):
						if '-' in port:
							port_range = list(map(str, range(int(port.split('-')[0]), int(port.split('-')[1]) + 1)))
							for p in port_range:
								if p.isdigit() and int(p) in range(1, 65536):
									ip_and_ports.append(p)
								else:
									conn.close()
									raise ArgumentError('{1}[!] Invalid port given to {0}show'.format(colors.RESET, colors.RED))
						elif port.isdigit() and int(port) in range(1, 65536):
							ip_and_ports.append(port)
						else:
							conn.close()
							raise ArgumentError('{1}[!] Invalid port given to {0}show'.format(colors.RESET, colors.RED))
			elif len(args) == 1:
				ip_and_ports.extend(range(1, 65536))
			try:
				cur.execute('SELECT * from nmap_data WHERE ip_addr=(?) AND port IN ({0})'.format(','.join('?'*(len(ip_and_ports) - 1))), ip_and_ports)
				results = cur.fetchall()
			except sqlite3.OperationalError:
				raise sqlite3.OperationalError
			for result in results:
				table.append_row([result[0], result[1], result[2], result[3], result[4], result[5]])
			conn.close()
			print(table)
			return
		conn.close()
		raise ArgumentError('{1}[!] Invalid argument given to {0}show'.format(colors.RESET, colors.RED))
	if not args:
		# If there's no arguments, return a table with all IPs and their open ports
		table.column_headers = ['IP', 'PORTS']
		table.column_alignments['PORTS'] = BeautifulTable.ALIGN_LEFT
		try:
			cur.execute('SELECT ip_addr, port FROM nmap_data WHERE port IS NOT NULL AND port <> \'\'')
			results = cur.fetchall()
		except sqlite3.OperationalError:
			raise sqlite3.OperationalError
		current_ip = []
		current_ports = []
		for result in results:
			if not current_ip:
				current_ip.append(result[0])
				current_ports.append(result[1])
				continue
			if result[0] == current_ip[0]:
				if result[1] not in current_ports:
					current_ports.append(result[1])
					if results.index(result) == len(results) - 1:
						pass
					else:
						continue
			table.append_row([current_ip[0], ', '.join(current_ports)])
			current_ip.pop()
			del current_ports[:]
			current_ip.append(result[0])
			current_ports.append(result[1])
		conn.close()
		print(table)
		print('{2}{1}\n[*] Use {0}show <IP> <PORTS> {2}{1}to get more information about a specific host.{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD))
		print('{2}{1}[*] {0}<PORTS> {2}{1}can be a list of ports and ranges e.g.{0} show 192.168.1.1 22,23,50-80,443'.format(colors.RESET, colors.YELLOW, colors.BOLD))
		print('{2}{1}[*] If a port or list of ports is not given to {0}show{2}{1} all ports will displayed.{0} '.format(colors.RESET, colors.YELLOW, colors.BOLD))
		return
	conn.close()
	raise ArgumentError('{1}[!] Invalid argument given to {0}show.'.format(colors.RESET, colors.RED))