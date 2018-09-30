#!/usr/bin/python3

import sqlite3

from modules.lib.colors import colors
from modules.lib.errors import ArgumentError

def portscan_get(db_file, args):
	"""Prints module configs to the terminal."""
	args = [arg.lower() for arg in args.split()]
	conn = sqlite3.connect(db_file)
	cur = conn.cursor()
	if args[0] == 'masscan':
		if args[1] == 'rate' or args[1] == 'configs':
			try:
				cur.execute('SELECT rate FROM masscan_configs')
				masscan_current_rate = cur.fetchone()[0]
				print('{1}[*] Masscan rate currently set to: {0}{2}'.format(colors.RESET, colors.YELLOW, masscan_current_rate))
			except sqlite3.OperationalError:
				raise sqlite3.OperationalError
			finally:
				if args[1] == 'rate':
					conn.close()
					return
		if args[1] == 'output' or args[1] == 'configs':
			try:
				cur.execute('SELECT output FROM masscan_configs')
				masscan_current_output = cur.fetchone()[0]
				print('{1}[*] Masscan output currently set to: {0}{2}'.format(colors.RESET, colors.YELLOW, masscan_current_output))
			except sqlite3.OperationalError:
				raise sqlite3.OperationalError
			finally:
				conn.close()
				return
		conn.close()
		raise ArgumentError('{1}[!] Invalid argument given to {0}get.'.format(colors.RESET, colors.RED))
	if args[0] == 'nmap':
		if args[1] == 'output' or args[1] == 'configs':
			try:
				cur.execute('SELECT output FROM nmap_configs')
				nmap_current_output = cur.fetchone()[0]
				print('{1}[*] Nmap output currently set to: {0}{2}'.format(colors.RESET, colors.YELLOW, nmap_current_output))
			except sqlite3.OperationalError:
				raise sqlite3.OperationalError
			finally:
				conn.close()
				return
		conn.close()
		raise ArgumentError('{1}[!] Invalid argument given to {0}get.'.format(colors.RESET, colors.RED))
	conn.close()
	raise ArgumentError('{1}[!] Invalid argument given to {0}get.'.format(colors.RESET, colors.RED))