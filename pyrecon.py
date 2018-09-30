#!/usr/bin/python3

"""Pyrecon: An external pentest and web app automation framework.

Uses SQLite databases to store project data.

STAGE:
Refactoring and reading up on class inheritence to create a more logical flow
between Pyrecon contexts. ProjectCmd, ActiveCmd and the future PassiveCmd will
all inherit from MainCmd.

Still needs to be refactored:
modules.core.ActiveCmd.set

Implement more error handling:
modules.core.ActiveCmd.run
"""

import os
import sys
import cmd

from modules.core import MainCmd
from modules.lib.colors import colors

if __name__ == '__main__':
	if os.geteuid() != 0:
		sys.exit('{2}{1}[!] Run as root.{0}'.format(colors.RESET, colors.RED, colors.BOLD))
	try:
		# Make sure the db directory exists
		os.makedirs(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'databases'))
	except FileExistsError:
		pass
	maincmd = MainCmd()
	maincmd.cmdloop_no_interrupt()

