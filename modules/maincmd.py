#!/usr/bin/python3
"""Pyrecon: An external pentest and web app automation framework.

Uses SQLite databases to store project data.
"""
__version__ = '0.1'
__author__ = 'Dan Hollis'
__status__ = 'Prototype'

import cmd
import csv
import os
import pwd
import sqlite3
import sys

from beautifultable import BeautifulTable
from datetime import datetime
from pyfiglet import figlet_format
from termcolor import cprint
from modules.colors import colors
from modules.extrec import *
from modules.parsers import ip_validator
from modules.webrec import *

class MainCmd(cmd.Cmd):
	"""Main command loop for pyrecon."""
	_username = pwd.getpwuid(os.getuid()).pw_name
	_db_file = ''
	_project = ''
	_db_directory = os.path.join((os.path.dirname(os.path.realpath(__file__))), 'pyrecon_dbs')
	prompt = '{3}{2}{4}@pyrecon{0}> '.format(colors.RESET, colors.BLUE, colors.RED, colors.BOLD, _username)
	ruler = '{2}{1}-{0}'.format(colors.RESET, colors.BLUE, colors.BOLD)
	doc_header = '{2}{1}Type help <command> for info on using each command:{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD)
	intro = '{3}{2}[*] Type help for available commands and their options.\n' \
		'[*] Currently available commands are:\n{0}{3}{1}{4}{0}\n' \
		'{3}{1}|{0}\t\t    select <project_name>\t\t\t{3}{1}|{0}\n{3}{1}{4}{0}\n' \
		'{3}{1}|{0} init <project_name> <target_domain> </path/to/project/output> {3}{1}|{0}\n{3}{1}{4}{0}\n'.format(colors.RESET, 
		colors.BLUE, colors.YELLOW, colors.BOLD, '-' * 65)

	def preloop(self):
		os.system('cls' if os.name == 'nt' else 'clear')
		cprint(figlet_format('Pyrecon', font='banner3'), 'blue', attrs=['bold']) # Lazy ascii art

	def default(self, line):
		self.stdout.write('{1}[!] Unknown command:{0} {2}\n'.format(colors.RESET, colors.RED, line))
		self.do_help('')

	def do_help(self, *args):
		"""Get info on available commands."""
		cmd.Cmd.do_help(self, *args)
		if not all(args):
			print('{2}{1}[*] Commands are available depending upon the context of Pyrecon.\n'
				'    The prompt will change when a new context is entered, and a\n'
				'    new help menu can be shown.\n'.format(colors.RESET, colors.YELLOW, colors.BOLD))

	def do_init(self, args):
		"""Initialize database and file structure for project."""
		args = [arg.lower() for arg in args.split()]
		if len(args) != 3:
			print('{1}[!] Invalid number of agruments given to init.{0}'.format(colors.RESET, colors.RED))
			self.do_help('init')
			return
		self._project = args[0]
		target_host = args[1]
		output_directory = os.path.abspath(args[2])
		if not os.path.exists(output_directory):
			os.makedirs(output_directory)
		open(os.path.join(output_directory, 'domains.txt'), 'w').close() # create empty target domains file
		open(os.path.join(output_directory, 'subnets.txt'), 'w').close() # create empty target subnets file
		self._db_file = os.path.join(self._db_directory, '{0}.db'.format(self._project))
		if os.path.exists(self._db_file):
			os.system('cls' if os.name == 'nt' else 'clear')
			print('{2}{1}[+] Database already initilialized for project {0}{3}.'.format(colors.RESET, colors.GREEN, colors.BOLD, self._project))
			print('{2}{1}[*] Selecting project {0}{3}'.format(colors.RESET, colors.YELLOW, colors.BOLD, self._project))
			projectcmd = ProjectCmd()
			projectcmd._username = self._username
			projectcmd._db_file = self._db_file
			projectcmd._project = self._project
			projectcmd.prompt = '{4}{2}{1}{3}{0}> '.format(colors.RESET, colors.BLUE, colors.BOLD, self._project, self.prompt[:-1])
			projectcmd.cmdloop()
			return
		try:
			conn = sqlite3.connect(self._db_file)
			cur = conn.cursor()
			# Initialize project configs table
			cur.execute('CREATE TABLE project (project text, target text, output text)')
			with conn:
				cur.execute('INSERT INTO project (project, target, output) VALUES(?,?,?)', (self._project, target_host, output_directory))
			# Initialize masscan configs table
			cur.execute('CREATE TABLE masscan (rate text, output text)')
			cur.execute('CREATE TABLE masscan_outputs (output_id integer PRIMARY KEY, time_stamp text, masscan_output text)')
			with conn:
				masscan_output = os.path.join(output_directory, 'external_recon/portscan/masscan')
				cur.execute('INSERT INTO masscan (rate, output) VALUES(?,?)', (1000, masscan_output))
			# Initialize nmap configs table
			cur.execute('CREATE TABLE nmap (output text)')
			cur.execute('CREATE TABLE nmap_outputs (ip_addr text, fqdn text, os text, protocol text, port text, service text)')
			with conn:
				nmap_output = os.path.join(output_directory, 'external_recon/portscan/nmap')
				cur.execute('INSERT INTO nmap (output) VALUES(?)', (nmap_output,))
			conn.close()
			os.system('cls' if os.name == 'nt' else 'clear')
			print('{2}{1}[*] Database initialized for project {0}{3}.'.format(colors.RESET, colors.YELLOW, colors.BOLD, self._project))
			projectcmd = ProjectCmd()
			projectcmd._username = self._username
			projectcmd._db_file = self._db_file
			projectcmd._project = self._project
			projectcmd.prompt = '{4}{2}{1}{3}{0}> '.format(colors.RESET, colors.BLUE, colors.BOLD, self._project, self.prompt[:-1])
			projectcmd.cmdloop()
			return
		except sqlite3.OperationalError as error:
			print('{1}[!] SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
			conn.close()
			return

	def help_init(self):
		print('usage: init <PROJECT> <TARGET> <OUTPUT>\n')
		print('{2}{1}Init is used to initialize a project database:{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD))
		print('\t<PROJECT>\tThe name of the project.')
		print('\t<TARGET>\tThe target domain. Currently accepts only 1 target domain.')
		print('\t<OUTPUT>\tThe path to your output directory. Pyrecon will build upon this directory as modules are executed. Module\n'
			'\t\t\toutputs can be indiviudally configured, but the intention is to use a single main output directory for\n'
			'\t\t\tall modules.\n')

	def do_select(self, args):
		"""Select a working project. Must first initialize a database for the project."""
		args = [arg.lower() for arg in args.split()]
		if len(args) != 1:
			print('{1}[!] Invalid number of arguments given to select.{0}'.format(colors.RESET, colors.RED))
			self.do_help('select')
			return
		self._project = args[0]
		self._db_file = os.path.join(self._db_directory, '{0}.db'.format(self._project))
		if not os.path.isfile(self._db_file):
			print('{1}[!] Database not found for project{0} {2}'.format(colors.RESET, colors.RED, self._project))
			return
		os.system('cls' if os.name == 'nt' else 'clear')
		print('{2}{1}[*] Database selected for project {0}{3}.'.format(colors.RESET, colors.YELLOW, colors.BOLD, self._project))
		projectcmd = ProjectCmd()
		projectcmd._username = self._username
		projectcmd._db_file = self._db_file
		projectcmd._project = self._project
		projectcmd.prompt = '{4}{2}{1}{3}{0}> '.format(colors.RESET, colors.BLUE, colors.BOLD, self._project, self.prompt[:-1])
		projectcmd.cmdloop()
		return

	def help_select(self):
		print('usage: select <PROJECT>\n')
		print('{2}{1}Select is used to select a working project database:{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD))
		print('\t<PROJECT>\tThe name of the project.\n')

	def complete_select(self, text, line, begidx, endidx):
		db_list = [db_file.rstrip('.db') for db_file in os.listdir(self._db_directory)]
		if not text:
			return db_list[:]
		return [project for project in db_list if project.lower().startswith(text.lower())]

	def do_exit(self, args):
		"""Exit the program."""
		print('{1}Bye{0}'.format(colors.RESET, colors.GREEN))
		return True

	def do_shell(self, args):
		"""Execute shell commands. ! can be used as an alias for shell e.g. ! ls"""
		os.system(args)

	def do_clear(self, args):
		"""Clears the terminal."""
		os.system('cls' if os.name == 'nt' else 'clear')

class ProjectCmd(cmd.Cmd):
	"""Command loop after project selected or initialized."""
	_db_file = ''
	_username = ''
	_project = ''
	prompt = ''
	ruler = '{2}{1}-{0}'.format(colors.RESET, colors.BLUE, colors.BOLD)
	doc_header = '{2}{1}Type help <command> for info on using each command:{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD)
	intro = '{3}{2}[*] Type help for available commands and their options.\n' \
		'[*] Currently available commands are:\n{0}{3}{1}{4}{0}\n' \
		'{3}{1}|{0}\tdns (initializes dns modules)\t    {3}{1}|{0}\n{3}{1}{4}{0}\n' \
		'{3}{1}|{0}  portscan (initializes portscan modules){3}{1}  |{0}\n{3}{1}{4}{0}\n'.format(colors.RESET, colors.BLUE, 
		colors.YELLOW, colors.BOLD, '-' * 45)

	def default(self, line):
		self.stdout.write('{1}[!] Unknown command:{0} {2}\n'.format(colors.RESET, colors.RED, line))
		self.do_help('')

	def do_help(self, *args):
		"""Get info on available commands."""
		cmd.Cmd.do_help(self, *args)
		if not all(args):
			print('{2}{1}[*] Commands are available depending upon the context of Pyrecon.\n'
				'    The prompt will change when a new context is entered, and a\n'
				'    new help menu can be shown.\n'.format(colors.RESET, colors.YELLOW, colors.BOLD))

	def do_dns(self, args):
		"""Run passive or active DNS recon."""
		os.system('cls' if os.name == 'nt' else 'clear')
		modulecmd = DnsCmd()
		modulecmd.prompt = '{3}{2}{1}dns{0}> '.format(colors.RESET, colors.BLUE, colors.BOLD, self.prompt[:-1])
		modulecmd._username = self._username
		modulecmd._db_file = self._db_file
		modulecmd._project = self._project
		modulecmd.cmdloop()

	def help_dns(self):
		print('usage: dnsrecon\n')
		print('{2}{1}Initializes dnsrecon modules and commands:{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD))
		print('\tAfter initializing dnsrecon modules, Pyrecon will enter a different context with commands\n'
			'\tseperate from the current project context. Commands will be made available to run modules\n'
			'\tseperately or together, and to visualize data like discovered subnet and ASN info.\n'
			'\tGraphs and improved table visualizations of data currently in the works.\n')

	def do_portscan(self, args):
		"""Enables portscan modules (nmap, masscan)."""
		os.system('cls' if os.name == 'nt' else 'clear')
		print('{2}{1}[*] Commands and modules initialized for {0}portscan.'.format(colors.RESET, colors.YELLOW, colors.BOLD))
		modulecmd = PortscanCmd()
		modulecmd.prompt = '{3}{2}{1}portscan{0}> '.format(colors.RESET, colors.BLUE, colors.BOLD, self.prompt[:-1])
		modulecmd._username = self._username
		modulecmd._db_file = self._db_file
		modulecmd._project = self._project
		modulecmd.cmdloop()
		return

	def help_portscan(self):
		print('usage: portscan\n')
		print('{2}{1}Initializes portscan modules and commands:{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD))
		print('\tAfter initializing portscan modules, Pyrecon will enter a different context with commands\n'
			'\tseperate from the current project context. Commands will be made available to run modules\n'
			'\tseperately or together, and to visualize data like port information for selected hosts.\n'
			'\tGraphs and improved table visualizations of host data currently in the works.\n')

	def do_back(self, args):
		"""Leaves the currently selected project."""
		maincmd = MainCmd()
		maincmd.prompt = '{3}{2}{4}@pyrecon{0}:{3}{1}pyrecon{0}> '.format(colors.RESET, colors.BLUE, colors.RED, colors.BOLD, self._username)
		maincmd._db_file = ''
		maincmd._project = ''
		os.system('cls' if os.name == 'nt' else 'clear')
		cprint(figlet_format('Pyrecon', font='banner3'), 'blue', attrs=['bold']) # Lazy ascii art
		print('{2}{1}[*] Returned from {0}{3} {2}{1}to main context.{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD, self._project))
		print('{3}{2}[*] Type help for available commands and their options.\n'
			'[*] Currently available commands are:\n{0}{3}{1}{4}{0}\n'
			'{3}{1}|{0}\t\t    select <project_name>\t\t\t{3}{1}|{0}\n{3}{1}{4}{0}\n'
			'{3}{1}|{0} init <project_name> <target_domain> </path/to/project/output> {3}{1}|{0}\n{3}{1}{4}{0}\n'.format(colors.RESET, colors.BLUE, 
			colors.YELLOW, colors.BOLD, '-' * 65))
		return True

	def do_exit(self, args):
		"""Exit the program."""
		sys.exit('{1}Bye{0}'.format(colors.RESET, colors.GREEN))

	def do_shell(self, args):
		"""Execute shell commands. ! can be used as an alias for shell e.g. ! ls"""
		os.system(args)

	def do_clear(self, args):
		"""Clears the terminal."""
		os.system('cls' if os.name == 'nt' else 'clear')

class PortscanCmd(cmd.Cmd):
	"""Command loop for portscan modules"""
	_db_file = ''
	_username = ''
	_project = ''
	prompt = ''
	ruler = '{2}{1}-{0}'.format(colors.RESET, colors.BLUE, colors.BOLD)
	doc_header = '{2}{1}Type help <command> for info on using each command:{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD)
	intro = '{3}{2}[*] Type help for available commands and their options.\n' \
		'[*] Currently available commands are:\n{0}{3}{1}{4}{0}\n' \
		'{3}{1}|{0}\t   get <module> [options]{3}{1}\t    |{0}\n{3}{1}{4}{0}\n' \
		'{3}{1}|{0}\t   set <module> [options]{3}{1}\t    |{0}\n{3}{1}{4}{0}\n' \
		'{3}{1}|{0}\t   run (executes module){3}{1}\t    |{0}\n{3}{1}{4}{0}\n' \
		'{3}{1}|{0}\t       show [options]{3}{1}\t\t    |{0}\n{3}{1}{4}{0}\n'.format(colors.RESET, colors.BLUE, 
		colors.YELLOW, colors.BOLD, '-' * 45)
	
	def default(self, line):
		self.stdout.write('{1}[!] Unknown command:{0} {2}\n'.format(colors.RESET, colors.RED, line))
		self.do_help('')

	def do_help(self, *args):
		"""Get info on available commands."""
		cmd.Cmd.do_help(self, *args)
		if not all(args):
			print('{2}{1}[*] Commands are available depending upon the context of Pyrecon.\n'
				'    The prompt will change when a new context is entered, and a\n'
				'    new help menu can be shown.\n'.format(colors.RESET, colors.YELLOW, colors.BOLD))

	def do_run(self, args):
		"""Run the selected module."""
		args = [arg.lower() for arg in args.split()]
		if len(args) > 1:
			print('{1}[!] Invalid number of arguments given to run.{0}'.format(colors.RESET, colors.RED))
			self.do_help('run')
			return
		db_file = self._db_file
		if args:
			run_module = args[0].lower()
		else:
			run_module = ['masscan', 'nmap']
		if 'masscan' in run_module:
			conn = sqlite3.connect(db_file)
			cur = conn.cursor()
			try:
				# Get the main output directory for easy access of files in modules
				cur.execute('SELECT output FROM project')
				output_directory = cur.fetchone()[0]
				# Initialize masscan settings
				cur.execute('SELECT rate FROM masscan')
				masscan_rate = cur.fetchone()[0]
				cur.execute('SELECT output FROM masscan')
				masscan_directory = cur.fetchone()[0]
				masscan_json = os.path.join(masscan_directory, 'masscan.json')
				os.makedirs(masscan_directory, exist_ok=True)
				# Initialize nmap settings
				cur.execute('SELECT output from nmap')
				nmap_directory = cur.fetchone()[0]
				os.makedirs(nmap_directory, exist_ok=True)
			except sqlite3.OperationalError as error:
				print('{1}[!] Database error: {0}{2}'.format(colors.RESET, colors.RED, error))
				conn.close()
				return
			try:
				time_stamp = datetime.now().strftime("%c")
				pyrecon_masscan(masscan_directory, output_directory, masscan_rate)
				with conn:
					cur.execute('INSERT INTO masscan_outputs (output_id, time_stamp, masscan_output) VALUES (?,?,?)', (None, time_stamp, masscan_json))
				if run_module == 'masscan':
					return
			except FileExistsError:
				print('{1}[*] Masscan output already exists:{0} {2}'.format(colors.RESET, colors.YELLOW, masscan_json))
				print('{1}[*] Skipping masscan...\n{0}'.format(colors.RESET, colors.YELLOW))
				conn.close()
				if run_module == 'masscan':
					return
				pass
			except FileNotFoundError:
				print('{1}[!] File not found or empty: {0}{2} {1}\n[!] Run dns modules to gather subnets or input them' 
					' into the subnets file as line seperated values.{0}'.format(colors.RESET, colors.RED, os.path.join(output_directory, 'subnets.txt')))
				conn.close()
				return
			except Exception as error:
				print(error)
				print('{1}[!] Received unhandled error while running masscan. Returning to portscan prompt.{0}'.format(colors.RESET, colors.RED))
				conn.close()
				return
		if 'nmap' in run_module:
			conn = sqlite3.connect(db_file)
			cur = conn.cursor()
			try:
				time_stamp = datetime.now().strftime("%c")
				pyrecon_nmap(nmap_directory, output_directory)
				with conn:
					nmap_csv = os.path.join(nmap_directory, 'nmap.csv')
					with open(nmap_csv, 'r') as nmap_csv_file:
						reader = csv.DictReader(nmap_csv_file)
						for row in reader:
							# Insert nmap csv rows into nmap db table
							cur.execute('INSERT INTO nmap_outputs (ip_addr, fqdn, os, protocol, port, service) VALUES (?,?,?,?,?,?)', 
								(row["IP"], row["FQDN"], row["OS"], row["PROTOCOL"], row["PORT"], row["SERVICE"]))
							return
			except FileExistsError:
				print('{1}[*] Nmap output already exists:{0} {2}'.format(colors.RESET, colors.YELLOW, nmap_directory))
				print('{1}[*] Skipping nmap...{0}'.format(colors.RESET, colors.YELLOW))
				conn.close()
				return
			except Exception as error:
				print(error)
				print('{1}[!] Received unhandled error while running nmap. Returning to portscan prompt.{0}'.format(colors.RESET, colors.RED))
				conn.close()
				return
		print('{1}[!] Invalid agrument given to run.{0}'.format(colors.RESET, colors.RED))
		self.do_help('run')
		return

	def do_show(self, args):
		"""Prints selected module output to the terminal."""
		args = [arg.lower() for arg in args.split()]
		db_file = self._db_file
		table = BeautifulTable()
		if len(args) == 1 and not (ip_validator.is_valid_ipv4(args[0]) or ip_validator.is_valid_ipv6(args[0])):
			table.column_headers = ['IP', 'FQDN', 'OS', 'PROTOCOL', 'PORT', 'SERVICE']
			conn = sqlite3.connect(db_file)
			cur = conn.cursor()
			if args[0].lower() == 'webservers':
				ports = ['80','443','8080','8443']
				cur.execute('SELECT * from nmap_outputs WHERE port IN (?,?,?,?)', ports)
				for result in cur.fetchall():
					table.append_row([result[0], result[1], result[2], result[3], result[4], result[5]])
				print(table)
				conn.close()
				return
			print('{1}[!] Invalid argument given to show.{0}'.format(colors.RESET, colors.RED))
			self.do_help('show')
			conn.close()
			return
		elif len(args) == 2 or len(args) == 1:
			if ip_validator.is_valid_ipv4(args[0]) or ip_validator.is_valid_ipv6(args[0]):
				table.column_headers = ['IP', 'FQDN', 'OS', 'PROTOCOL', 'PORT', 'SERVICE']
				conn = sqlite3.connect(db_file)
				cur = conn.cursor()
				ip_and_ports = [args[0]]
				if len(args) == 2:
					if args[1].lower() == 'webservers':
						ip_and_ports.extend(['80','443','8080','8443'])
					else:
						for port in args[1].split(','):
							if '-' in port:
								port_range = list(range(int(port.split('-')[0]), int(port.split('-')[1]) + 1))
								for p in port_range:
									if p.isdigit() and int(p) in range(1, 65536):
										ip_and_ports.append(p)
									else:
										print('{1}[!] Invalid port given to {0}show'.format(colors.RESET, colors.RED))
										conn.close()
										return
							elif port.isdigit() and int(port) in range(1, 65536):
								ip_and_ports.append(port)
							else:
								print('{1}[!] Invalid port given to {0}show'.format(colors.RESET, colors.RED))
								conn.close()
								return
				elif len(args) == 1:
					ip_and_ports.extend(range(1, 65536))
				cur.execute('SELECT * from nmap_outputs WHERE ip_addr=(?) AND port IN ({0})'.format(','.join('?'*(len(ip_and_ports) - 1))), ip_and_ports)
				for result in cur.fetchall():
					table.append_row([result[0], result[1], result[2], result[3], result[4], result[5]])
				print(table)
				conn.close()
				return
			print('{1}[!] Invalid argument given to {0}show'.format(colors.RESET, colors.RED))
			self.do_help('show')
			return
		elif not args:
			table.column_headers = ['IP', 'PORTS']
			table.column_alignments['PORTS'] = BeautifulTable.ALIGN_LEFT
			conn = sqlite3.connect(db_file)
			cur = conn.cursor()
			cur.execute('SELECT ip_addr, port FROM nmap_outputs WHERE port IS NOT NULL AND port <> \'\'')
			current_ip = []
			current_ports = []
			for result in cur.fetchall():
				if not current_ip:
					current_ip.append(result[0])
					current_ports.append(result[1])
					continue
				if result[0] == current_ip[0]:
					if result[1] not in current_ports:
						current_ports.append(result[1])
						continue
				table.append_row([current_ip[0], ', '.join(current_ports)])
				current_ip.pop()
				del current_ports[:]
				current_ip.append(result[0])
				current_ports.append(result[1])
			print(table)
			print('{2}{1}\n[*] Use {0}show <IP> <PORTS> {2}{1}to get more information about a specific host.{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD))
			print('{2}{1}[*] {0}<PORTS> {2}{1}can be a list of ports and ranges e.g.{0} show 192.168.1.1 22,23,50-80,443'.format(colors.RESET, colors.YELLOW, colors.BOLD))
			print('{2}{1}[*] If a port or list of ports is not given to {0}show{2}{1} all ports will displayed.{0} '.format(colors.RESET, colors.YELLOW, colors.BOLD))
			conn.close()
			return
		print('{1}[!] Invalid argument given to show.{0}'.format(colors.RESET, colors.RED))
		self.do_help('show')
		return

	def help_show(self):
		print('usage: show [options]\n')
		print('{3}{1}[*] Arguments based upon current module context e.g. {0}{3}{2}portscan{0}> {3}{1}vs{0} {3}{2}dnsrecon{0}>'.format(colors.RESET, colors.YELLOW, colors.BLUE,
			colors.BOLD))
		print('\tshow webservers\t\tList webservers discovered across all hosts.')
		print('\tshow <IP> <ports>\tList given discovered open ports on given host IP.')
		print('\tshow <ports>\t\tList given discovered open ports across all hosts. Must\n'
			'\t\t\t\tbe a comma seperated list of ports and ranges e.g. 22,23,50-80,443')
		print('\tshow <IP>\t\tList all discovered open ports on given host IP.')
		print('\tshow\t\t\tIf no arguments are given, an overview of all hosts and their \n'
			'\t\t\t\tdiscovered open ports will be listed.\n')

	def complete_show(self, text, line, begidx, endidx):
		conn = sqlite3.connect(self._db_file)
		cur = conn.cursor()
		cur.execute('SELECT ip_addr FROM nmap_outputs WHERE port IS NOT NULL AND port <> \'\'')
		completions = [ip[0] for ip in cur.fetchall()]
		conn.close()
		if not text:
			completions.extend(['webservers'])
			return completions
		if begidx == 5 and text[0].isdigit():
			return [ip for ip in completions if ip.startswith(text)]
		if begidx == 5 and text[0] == 'w':
			return [option for option in ['webservers'] if option.startswith(text.lower())]

	def do_get(self, args):
		"""Get module options."""
		args = [arg.lower() for arg in args.split()]
		db_file = self._db_file
		conn = sqlite3.connect(db_file)
		cur = conn.cursor()
		if args[0] == 'masscan':
			if args[1] == 'rate' or args[1] == 'configs':
				try:
					cur.execute('SELECT rate FROM masscan')
					masscan_current_rate = cur.fetchone()[0]
					print('{1}[*] Masscan rate currently set to: {0}{2}'.format(colors.RESET, colors.YELLOW, masscan_current_rate))
				except sqlite3.OperationalError as error:
					print('{1}[!] Masscan rate get SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
				finally:
					if args[1].lower() == 'rate':
						conn.close()
						return
			if args[1] == 'output' or args[1] == 'configs':
				try:
					cur.execute('SELECT output FROM masscan')
					masscan_current_output = cur.fetchone()[0]
					print('{1}[*] Masscan output currently set to: {0}{2}'.format(colors.RESET, colors.YELLOW, masscan_current_output))
				except sqlite3.OperationalError as error:
					print('{1}[!] Masscan output get SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
				finally:
					conn.close()
					return
			print('{1}[!] Invalid option given masscan to get.{0}'.format(colors.RESET, colors.RED))
			self.do_help('get')
			conn.close()
			return
		if args[0] == 'nmap':
			if args[1] == 'output' or args[1] == 'configs':
				try:
					cur.execute('SELECT output FROM nmap')
					nmap_current_output = cur.fetchone()[0]
					print('{1}[*] Nmap output currently set to: {0}{2}'.format(colors.RESET, colors.YELLOW, nmap_current_output))
				except sqlite3.OperationalError as error:
					print('{1}[!] Nmap output get SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
				finally:
					conn.close()
					return
			print('{1}[!] Invalid option given nmap to get.{0}'.format(colors.RESET, colors.RED))
			self.do_help('get')
			conn.close()
			return
		print('{1}[!] Invalid option given to get.{0}'.format(colors.RESET, colors.RED))
		self.do_help('get')
		conn.close()
		return

	def help_get(self):
		print('usage: get <MODULE> [options]\n')
		print('{2}{1}Get is used to display (get) project module configurations:{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD))
		print('\t<MODULE> configs\tPrints all current configurations for the module.')
		print('\t<MODULE> output\t\tPrints the configured output directory for the module.')
		print('\tmasscan rate\t\tPrints the configured masscan rate.\n')

	def complete_get(self, text, line, begidx, endidx):
		if not text and not line:
			return ['masscan', 'nmap']
		if begidx == 4:
			return [module for module in ['masscan', 'nmap'] if module.startswith(text.lower())]
		if begidx == 9 and 'nmap' in line.split():
			return [option for option in ['output'] if option.startswith(text.lower())]
		if begidx == 12 and 'masscan' in line.split():
			return [option for option in ['rate', 'output'] if option.startswith(text.lower())]

	def do_set(self, args):
		"""Set module options."""
		args = [arg.lower() for arg in args.split()]
		db_file = self._db_file
		conn = sqlite3.connect(db_file)
		cur = conn.cursor()
		if args[0] == 'masscan':
			if args[1] == 'rate' and args[2].isdigit():
				try:
					with conn:
						cur.execute('UPDATE masscan SET rate = ?', (args[2],))
						print('{1}[*] Masscan rate is now set to: {0}{2}'.format(colors.RESET, colors.YELLOW, args[2]))
				except sqlite3.OperationalError as error:
					print('{1}[!] Masscan rate set SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
				finally:
					conn.close()
					return
			if args[1] == 'output':
				try:
					with conn:
						cur.execute('UPDATE masscan SET output = ?', (os.path.abspath(args[2]),))
						print('{1}[*] Masscan output is now set to: {0}{2}'.format(colors.RESET, colors.YELLOW, os.path.abspath(args[2])))
				except sqlite3.OperationalError as error:
					print('{1}[!] Masscan output set SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
				finally:
					conn.close()
					return
			print('{1}[!] Invalid option given to masscan set.{0}'.format(colors.RESET, colors.RED))
			self.do_help('set')
			conn.close()
			return
		if args[0] == 'nmap':
			if args[1] == 'output':
				try:
					with conn:
						cur.execute('UPDATE nmap SET output = ?', (os.path.abspath(args[2]),))
						print('{1}[*] Nmap output is now set to: {0}{2}'.format(colors.RESET, colors.YELLOW, os.path.abspath(args[2])))
				except sqlite3.OperationalError as error:
					print('{1}[!] Nmap output set SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
				finally:
					conn.close()
					return
			print('{1}[!] Invalid option given to nmap set.{0}'.format(colors.RESET, colors.RED))
			self.do_help('set')
			conn.close()
			return
		print('{1}[!] Invalid option given to set.{0}'.format(colors.RESET, colors.RED))
		self.do_help('set')
		conn.close()
		return

	def help_set(self):
		print('usage: set <MODULE> [options]\n')
		print('{2}{1}Set is used to change (set) project module configurations:{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD))
		print('\t<MODULE> output\t\tChanges the configured output directory for the module. Pyrecon is intended to keep all outputs\n'
			'\t\t\t\tcentralized to a main project directory with default module output directories, but the location\n\t\t\t\tcan be changed '
			'if a module must be executed more than once and a different output location is needed.')
		print('\tmasscan rate <INT>\tChanges the configured masscan rate.\n')

	def complete_set(self, text, line, begidx, endidx):
		if not text and not line:
			return ['masscan', 'nmap']
		if begidx == 4:
			return [module for module in ['masscan', 'nmap'] if module.startswith(text.lower())]
		if begidx == 9 and 'nmap' in line.split():
			return [option for option in ['output'] if option.startswith(text.lower())]
		if begidx == 12 and 'masscan' in line.split():
			return [option for option in ['rate', 'output'] if option.startswith(text.lower())]

	def do_back(self, args):
		"""Returns to poject prompt."""
		projectcmd = ProjectCmd()
		projectcmd._prompt = '{3}{2}{1}{4}{0}> '.format(colors.RESET, colors.BLUE, colors.BOLD, self.prompt[:-1], self._project)
		projectcmd._username = self._username
		projectcmd._db_file = self._db_file
		projectcmd._project = self._project
		os.system('cls' if os.name == 'nt' else 'clear')
		print('{2}{1}[*] Returned from {0}portscan {2}{1}to{0} {3}.'.format(colors.RESET, colors.YELLOW, colors.BOLD, self._project))
		print('{3}{2}[*] Type help for available commands and their options.\n'
		'[*] Currently available commands are:\n{0}{3}{1}{4}{0}\n'
		'{3}{1}|{0}\tdns (initializes dns modules)\t    {3}{1}|{0}\n{3}{1}{4}{0}\n'
		'{3}{1}|{0}  portscan (initializes portscan modules){3}{1}  |{0}\n{3}{1}{4}{0}\n'.format(colors.RESET, colors.BLUE, 
		colors.YELLOW, colors.BOLD, '-' * 45))
		return True

	def do_exit(self, args):
		"""Exit the program."""
		sys.exit('{1}Bye{0}'.format(colors.RESET, colors.GREEN))

	def do_shell(self, args):
		"""Execute shell commands. ! can be used as an alias for shell e.g. ! ls"""
		os.system(args)

	def do_clear(self, args):
		"""Clears the terminal."""
		os.system('cls' if os.name == 'nt' else 'clear')
		return
