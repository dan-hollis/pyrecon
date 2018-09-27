#!/usr/bin/python3
import socket

def is_valid_ipv4(address):
	try:
		socket.inet_pton(socket.AF_INET, address)
	except AttributeError:
		try:
			socket.inet_aton(address)
		except socket.error:
			return False
		return address.count('.') == 3
	except socket.error:
		return False

	return True

def is_valid_ipv6(address):
	try:
		socket.inet_pton(socket.AF_INET6, address)
	except socket.error:
		return False
	return True

