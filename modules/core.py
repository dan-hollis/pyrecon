#!/usr/bin/python3

"""Pyrecon: An external pentest and web app automation framework.

Uses SQLite databases to store project data.

STAGE:
Refactoring and reading up on class inheritence to create a more logical flow
between Pyrecon contexts. ProjectCmd, ActiveCmd and the future PassiveCmd will
all inherit from MainCmd. 

Still needs to be refactored:
ActiveCmd.set

Implement more error handling:
ActiveCmd.run
"""

__version__ = '0.1'
__author__ = 'Dan Hollis'
__status__ = 'Prototype'

import cmd
import os
import pwd
import sqlite3
import sys

from pyfiglet import figlet_format
from termcolor import cprint

import modules.commands
import modules.lib
import modules.lib.errors as errors

from modules.lib.colors import colors

class MainCmd(cmd.Cmd):
	"""Main command loop for pyrecon."""
	_db_file = ''
	_username = pwd.getpwuid(os.getuid()).pw_name
	_project = ''
	_db_directory = os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))), 'databases')
	_show_banner = True
	prompt = '{3}{2}{4}@pyrecon{0}> '.format(colors.RESET, colors.BLUE, colors.RED, colors.BOLD, _username)
	ruler = '{2}{1}-{0}'.format(colors.RESET, colors.BLUE, colors.BOLD)
	doc_header = '{2}{1}Type help <command> for info on using each command:{0}'.format(colors.RESET, colors.YELLOW, colors.BOLD)
	intro = '{3}{2}[*] Type help for available commands and their options.\n' \
		'[*] Currently available commands are:\n{0}{3}{1}{4}{0}\n' \
		'{3}{1}|{0}\t\t    select <project_name>\t\t\t{3}{1}|{0}\n{3}{1}{4}{0}\n' \
		'{3}{1}|{0} init <project_name> <target_domain> </path/to/project/output> {3}{1}|{0}\n{3}{1}{4}{0}\n'.format(colors.RESET, 
		colors.BLUE, colors.YELLOW, colors.BOLD, '-' * 65)

	def cmdloop_no_interrupt(self):
		"""Prevent KeyboardInterrupt from exiting."""
		while True:
			try:
				self.cmdloop()
				break
			except KeyboardInterrupt:
				self.intro = ''
				self._show_banner = False
				sys.stdout.write('^C\n')

	def preloop(self):
		if self._show_banner:
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
			projectcmd.cmdloop_no_interrupt()
			return
		try:
			modules.commands.db_init(self._db_file, args)
			os.system('cls' if os.name == 'nt' else 'clear')
			print('{2}{1}[*] Database initialized for project {0}{3}.'.format(colors.RESET, colors.YELLOW, colors.BOLD, self._project))
			projectcmd = ProjectCmd()
			projectcmd._username = self._username
			projectcmd._db_file = self._db_file
			projectcmd._project = self._project
			projectcmd.prompt = '{4}{2}{1}{3}{0}> '.format(colors.RESET, colors.BLUE, colors.BOLD, self._project, self.prompt[:-1])
			projectcmd.cmdloop_no_interrupt()
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
		projectcmd.cmdloop_no_interrupt()
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
	"""Command loop for module selection and initialization."""
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

	def cmdloop_no_interrupt(self):
		"""Prevent KeyboardInterrupt from exiting."""
		while True:
			try:
				self.cmdloop()
				break
			except KeyboardInterrupt:
				self.intro = ''
				sys.stdout.write('^C\n')

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
		"""Enables DNS modules (dnsrecon, whois)."""
		os.system('cls' if os.name == 'nt' else 'clear')
		modulecmd = PassiveCmd()
		modulecmd.prompt = '{3}{2}{1}dns{0}> '.format(colors.RESET, colors.BLUE, colors.BOLD, self.prompt[:-1])
		modulecmd._username = self._username
		modulecmd._db_file = self._db_file
		modulecmd._project = self._project
		modulecmd._module = 'dns'
		modulecmd.cmdloop_no_interrupt()

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
		modulecmd = ActiveCmd()
		modulecmd.prompt = '{3}{2}{1}portscan{0}> '.format(colors.RESET, colors.BLUE, colors.BOLD, self.prompt[:-1])
		modulecmd._username = self._username
		modulecmd._db_file = self._db_file
		modulecmd._project = self._project
		modulecmd._module = 'portscan'
		modulecmd.cmdloop_no_interrupt()
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

class ActiveCmd(cmd.Cmd):
	"""Command loop for active recon modules."""
	_db_file = ''
	_username = ''
	_project = ''
	_module = ''
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

	def cmdloop_no_interrupt(self):
		"""Prevent KeyboardInterrupt from exiting."""
		while True:
			try:
				self.cmdloop()
				break
			except KeyboardInterrupt:
				self.intro = ''
				sys.stdout.write('^C\n')
	
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
		try:
			if self._module == 'portscan':
				modules.commands.portscan_run(self._db_file, args)
		except FileExistsError as error:
			print(error)
			return
		except FileNotFoundError as error:
			print(error)
			return
		except errors.ArgumentError as error:
			print(error)
			return
		except sqlite3.OperationalError as error:
			print('{1}[!] SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
			return


	def do_show(self, args):
		"""Prints selected module output to the terminal."""
		try:
			if self._module == 'portscan':
				modules.commands.portscan_show(self._db_file, args)
				return
		except errors.ArgumentError as error:
			print(error)
			self.do_help('show')
			return
		except sqlite3.OperationalError as error:
			print('{1}[!] SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
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
		cur.execute('SELECT ip_addr FROM nmap_data WHERE port IS NOT NULL AND port <> \'\'')
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
		try:
			if self._module == 'portscan':
				modules.commands.portscan_get(self._db_file, args)
				return
		except errors.ArgumentError as error:
			print(error)
			self.do_help('get')
			return
		except sqlite3.OperationalError as error:
			print('{1}[!] SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
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
			return [option for option in ['output', 'configs'] if option.startswith(text.lower())]
		if begidx == 12 and 'masscan' in line.split():
			return [option for option in ['rate', 'output', 'configs'] if option.startswith(text.lower())]

	def do_set(self, args):
		"""Set module options."""
		try:
			if self._module == 'portscan':
				modules.commands.portscan_set(self._db_file, args)
				return
		except errors.ArgumentError as error:
			print(error)
			self.do_help('set')
			return
		except sqlite3.OperationalError as error:
			print('{1}[!] SQL error: {0}{2}'.format(colors.RESET, colors.RED, error))
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
