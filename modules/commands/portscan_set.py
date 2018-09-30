#!/usr/bin/python3

import sqlite3

from modules.lib.errors import ArgumentError

def portscan_set(db_file, args):
	args = [arg.lower() for arg in args.split()]
	conn = sqlite3.connect(db_file)
	cur = conn.cursor()
	if args[0] == 'masscan':
		if args[1] == 'rate' and len(args) == 3 and args[2].isdigit():
			try:
				with conn:
					cur.execute('UPDATE masscan_configs SET rate = ?', (args[2],))
					print('{1}[*] Masscan rate is now set to: {0}{2}'.format(colors.RESET, colors.YELLOW, args[2]))
			except sqlite3.OperationalError as error:
				print('{1}[!] Masscan rate set SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
			finally:
				conn.close()
				return
		if args[1] == 'output':
			try:
				with conn:
					cur.execute('UPDATE masscan_configs SET output = ?', (os.path.abspath(args[2]),))
					print('{1}[*] Masscan output is now set to: {0}{2}'.format(colors.RESET, colors.YELLOW, os.path.abspath(args[2])))
			except sqlite3.OperationalError as error:
				raise sqlite3.OperationalError
			finally:
				conn.close()
				return
	if args[0] == 'nmap':
		if args[1] == 'output':
			try:
				with conn:
					cur.execute('UPDATE nmap_configs SET output = ?', (os.path.abspath(args[2]),))
					print('{1}[*] Nmap output is now set to: {0}{2}'.format(colors.RESET, colors.YELLOW, os.path.abspath(args[2])))
			except sqlite3.OperationalError as error:
				raise sqlite3.OperationalError
			finally:
				conn.close()
				return
	conn.close()
	raise ArgumentError('{1}[!] Invalid option given to {0}set.'.format(colors.RESET, colors.RED))