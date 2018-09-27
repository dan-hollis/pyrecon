#!/usr/bin/python3
import os
import sys
import cmd
from modules.maincmd import MainCmd
from modules.colors import colors

if __name__ == '__main__':
	if os.geteuid() != 0:
		sys.exit('{2}{1}[!] Run as root.{0}'.format(colors.RESET, colors.RED, colors.BOLD))
	try:
		# Make sure the db directory exists
		os.makedirs(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'modules/pyrecon_dbs'))
	except FileExistsError:
		pass
	maincmd = MainCmd()
	maincmd.cmdloop()
