#!/usr/bin/python3
import os
import sqlite3

def db_init(db_file, args):
	"""Initializes project database"""
	project = args[0]
	target_host = args[1]
	output_directory = os.path.abspath(args[2])

	if not os.path.exists(output_directory):
		os.makedirs(output_directory)

	open(os.path.join(output_directory, 'domains.txt'), 'w').close() # create empty target domains file
	open(os.path.join(output_directory, 'subnets.txt'), 'w').close() # create empty target subnets file
	try:
		conn = sqlite3.connect(db_file)
		cur = conn.cursor()
		# Initialize project configs table
		cur.execute('CREATE TABLE project (project text, target text, output text)')
		with conn:
			cur.execute('INSERT INTO project (project, target, output) VALUES(?,?,?)', (project, target_host, output_directory))
		# Initialize masscan configs table
		cur.execute('CREATE TABLE masscan_configs (rate text, output text)')
		cur.execute('CREATE TABLE masscan_outputs (output_id integer PRIMARY KEY, time_stamp text, masscan_output text)')
		with conn:
			masscan_output = os.path.join(output_directory, 'external_recon/portscan/masscan')
			cur.execute('INSERT INTO masscan_configs (rate, output) VALUES(?,?)', (1000, masscan_output))
		# Initialize nmap configs table
		cur.execute('CREATE TABLE nmap_configs (output text)')
		cur.execute('CREATE TABLE nmap_outputs (output_id integer PRIMARY KEY, time_stamp text, nmap_output text)')
		cur.execute('CREATE TABLE nmap_data (ip_addr text, fqdn text, os text, protocol text, port text, service text)')
		with conn:
			nmap_output = os.path.join(output_directory, 'external_recon/portscan/nmap')
			cur.execute('INSERT INTO nmap_configs (output) VALUES(?)', (nmap_output,))
		conn.close()
	except sqlite3.OperationalError:
		raise sqlite3.OperationalError
