#!/usr/bin/python3
class colors:
	"""Colored terminal outputs"""
	# Colors can be added and they will be loaded throughout the program
	# To output "ok" in green:
	# print(colors.GREEN + "ok" + colors.RESET)
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	BLUE = '\033[94m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	RESET = '\033[0m'
