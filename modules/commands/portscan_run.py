#!/usr/bin/bash

import csv
import os
import sqlite3

from datetime import datetime

from modules.extrec import pyrecon_masscan
from modules.extrec import pyrecon_nmap
from modules.lib.colors import colors
from modules.lib.errors import ArgumentError

def portscan_run(db_file, args):
	args = [arg.lower() for arg in args.split()]
	if len(args) > 1:
		raise ArgumentError('{1}[!] Invalid number of arguments given to run.{0}'.format(colors.RESET, colors.RED))
	conn = sqlite3.connect(db_file)
	cur = conn.cursor()
	if args:
		run_module = args[0].lower()
	else:
		run_module = ['masscan', 'nmap']
	cur.execute('SELECT output FROM project')
	output_directory = cur.fetchone()[0]
	if 'masscan' in run_module:
		try:
			# Get the main output directory for easy access of files in modules
			# Initialize masscan settings
			cur.execute('SELECT rate FROM masscan_configs')
			masscan_rate = cur.fetchone()[0]
			cur.execute('SELECT output FROM masscan_configs')
			masscan_directory = cur.fetchone()[0]
			masscan_json = os.path.join(masscan_directory, 'masscan.json')
			os.makedirs(masscan_directory, exist_ok=True)
		except sqlite3.OperationalError:
			raise sqlite3.OperationalError
		try:
			time_stamp = datetime.now().strftime("%c")
			pyrecon_masscan(masscan_directory, output_directory, masscan_rate)
			with conn:
				cur.execute('INSERT INTO masscan_outputs (output_id, time_stamp, masscan_output) VALUES (?,?,?)', (None, time_stamp, masscan_json))
			if run_module == 'masscan':
				return
		except FileExistsError:
			if run_module == 'masscan':
				conn.close()
				raise FileExistsError('{1}[*] Masscan output already exists:{0} {2}'
					'\n{1}[*] Skipping masscan...\n{0}'.format(colors.RESET, colors.YELLOW, masscan_json))
			else:
				print('{1}[*] Masscan output already exists:{0} {2}\n{1}[*] Skipping masscan...\n{0}'.format(colors.RESET, colors.YELLOW, masscan_json))
				pass
		except FileNotFoundError:
			conn.close()
			raise FileNotFounedError('{1}[!] File not found or empty: {0}{2} {1}\n[!] Run dns modules to gather subnets or input them' 
				' into the subnets file as line seperated values.{0}'.format(colors.RESET, colors.RED, os.path.join(output_directory, 'subnets.txt')))

	if 'nmap' in run_module:
		try:
			# Initialize nmap settings
			cur.execute('SELECT output from nmap_configs')
			nmap_directory = cur.fetchone()[0]
			os.makedirs(nmap_directory, exist_ok=True)
			time_stamp = datetime.now().strftime("%c")
			pyrecon_nmap(nmap_directory, output_directory)
			with conn:
				cur.execute('INSERT INTO nmap_outputs (output_id, time_stamp, nmap_output) VALUES (?,?,?)', (None, time_stamp, nmap_directory))
				nmap_csv = os.path.join(nmap_directory, 'nmap.csv')
				with open(nmap_csv, 'r') as nmap_csv_file:
					reader = csv.DictReader(nmap_csv_file)
					for row in reader:
						# Insert nmap csv rows into nmap db table
						cur.execute('INSERT INTO nmap_data (ip_addr, fqdn, os, protocol, port, service) VALUES (?,?,?,?,?,?)',
							(row["IP"], row["FQDN"], row["OS"], row["PROTOCOL"], row["PORT"], row["SERVICE"]))
					return
		except FileExistsError:
			conn.close()
			raise FileExistsError('{1}[*] Nmap output already exists:{0} {2}'
				'\n{1}[*] Skipping nmap...\n{0}'.format(colors.RESET, colors.YELLOW, nmap_directory))
		except FileNotFoundError:
			conn.close()
			raise FileNotFounedError('{1}[!] File not found or empty: {0}{2} {1}\n[!] Run dns modules to gather subnets or input them' 
				' into the subnets file as line seperated values.{0}'.format(colors.RESET, colors.RED, os.path.join(output_directory, 'subnets.txt')))
	conn.close()
	raise ArgumentError('{1}[!] Invalid argument given to {0}run.'.format(colors.RESET, colors.RED))
