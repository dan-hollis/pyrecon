#!/usr/bin/python3
class colors:
	"""Colored terminal outputs"""
	# Colors can be added and they will be loaded throughout the program
	# To output "test" in green:
	# print(colors.GREEN + "test" + colors.RESET)
	# print({1}test{0}.format(colors.RESET, colors.GREEN))
	GREEN = '\033[92m'
	YELLOW = '\033[93m'
	BLUE = '\033[94m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	RESET = '\033[0m'
