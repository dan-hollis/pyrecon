#!/usr/bin/python3
import requests
from modules.lib.colors import colors
import json
requests.packages.urllib3.disable_warnings() # Disable SSL certificate warnings
import os

def get_live_webdomains(get_live_webdomains_configs):
	subdomains_all_file = get_live_webdomains_configs["subdomains_all_file"]
	subdomains_live_file = get_live_webdomains_configs["subdomains_live_file"]
	output_directory = get_live_webdomains_configs["output_directory"]
	timeout = int(get_live_webdomains_configs["timeout"])
	retries = int(get_live_webdomains_configs["retries"]) + 1
	#ports = ['80', '8080', '443', '8443']
	verbose = get_live_webdomains_configs["verbose"]
	with open(subdomains_all_file, 'r') as read_subdomains:
		subdomains = sorted(set(subdomain.replace('www.', '') for subdomain in read_subdomains.read().splitlines()))
	live_subdomains = {"http_responses": [], "https_responses": []} 
	down_subdomains = {"http_responses": [], "https_responses": []}
	
	print('{1}{4:^80}{0}{3}|{0}{2}{5:^80}{0}\n{3}{6}{0}'.format(colors.RESET, colors.GREEN, colors.RED, colors.BLUE, 'LIVE', 'DOWN', '-' * 160))
	
	for subdomain in subdomains:
		unicode_error = False
		for port in ['80', '8080']:
			if unicode_error:
				break
			for number_retries in range(retries):
				try:
					request = requests.get('http://{0}:{1}'.format(subdomain, port), timeout=timeout, verify=False)
					try:
						if request.status_code not in range(400,499) or request.status_code == 404:
							request.raise_for_status() # returns HTTPError if an unsuccessful status code is returned
						http_response = str(request.status_code)
						if len(subdomain) > 80:
							if port not in range(400,499):
								print('{0:^80.80}{3}|{4}{1:^80.80}\n{3}{2}{4}'.format('http://' + subdomain + ':' + port + colors.GREEN + 
									' [' + http_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
							else:
								print('{0:^80.80}{3}|{4}{1:^80.80}\n{3}{2}{4}'.format('http://' + subdomain + ':' + port + colors.YELLOW + 
									' [' + http_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))		
						else:
							if port not in range(400,499):
								print('{0:^80.80}{3}|{4}{1:^80.80}\n{3}{2}{4}'.format('http://' + subdomain + ':' + port + colors.GREEN + 
									' [' + http_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
							else:
								print('{0:^80.80}{3}|{4}{1:^80.80}\n{3}{2}{4}'.format('http://' + subdomain + ':' + port + colors.YELLOW + 
									' [' + http_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
						live_subdomains["http_responses"].append({"port": '{0}'.format(port), "response": http_response, 
							"subdomain": '{0}'.format(subdomain)})
						break
					except requests.exceptions.HTTPError:
						bad_http_response = str(request.status_code)
						if len(subdomain) > 80:
							print('{1:^80.80}{3}|{4}{0:^80.80}\n{3}{2}{4}'.format('http://' + subdomain + ':' + port + colors.RED + 
								' [' + bad_http_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
						else:
							print('{1:^80.80}{3}|{4}{0:^89.80}\n{3}{2}{4}'.format('http://' + subdomain + ':' + port + colors.RED + 
								' [' + bad_http_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))

						down_subdomains["http_responses"].append({"port": '{0}'.format(port), "response": bad_http_response, "subdomain": '{0}'.format(subdomain)})
						break
				except requests.exceptions.Timeout:
					if number_retries + 1 == retries:
						bad_http_response = 'Timed Out'
						if verbose:
							if len(subdomain) > 80:
								print('{1:^80.80}{3}|{4}{0:^80.80}\n{3}{2}{4}'.format('http://' + subdomain + ":" + port + colors.RED + 
									' [TIMED OUT]' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
							else:
								print('{1:^80.80}{3}|{4}{0:^89.80}\n{3}{2}{4}'.format('http://' + subdomain + ":" + port + colors.RED + 
									' [TIMED OUT]' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
						down_subdomains["http_responses"].append({"port": '{0}'.format(port), "response": bad_http_response, "subdomain": '{0}'.format(subdomain)})
					else:
						continue
				except requests.exceptions.ConnectionError:
					bad_http_response = 'Connection Error'
					if verbose:
						if len(subdomain) > 80:
							print('{1:^80.80}{3}|{4}{0:^80.80}\n{3}{2}{4}'.format('http://' + subdomain + ":" + port + colors.RED + 
								' [CONNECTION ERROR]' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
						else:
							print('{1:^80.80}{3}|{4}{0:^89.80}\n{3}{2}{4}'.format('http://' + subdomain + ":" + port + colors.RED + 
								' [CONNECTION ERROR]' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
					down_subdomains["http_responses"].append({"port": '{0}'.format(port), "response": bad_http_response, "subdomain": '{0}'.format(subdomain)})
					break
				except UnicodeError:
					# catch improperly formatted domain names
					unicode_error = True
					if verbose:
						if len(subdomain) > 80:
							print('{1:^80.80}{3}|{4}{0:^80.80}\n{3}{2}{4}'.format(subdomain + colors.RED + ' [UNICODE ERROR]' + 
								colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
						else:
							print('{1:^80.80}{3}|{4}{0:^89.80}\n{3}{2}{4}'.format(subdomain + colors.RED + ' [UNICODE ERROR]' + 
								colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
					bad_http_response = 'Unicode Error'
					bad_https_response = 'Unicode Error'
					down_subdomains["http_responses"].append({"port": '{0}'.format(port), "response": bad_http_response, "subdomain": '{0}'.format(subdomain)})
					down_subdomains["https_responses"].append({"port": '{0}'.format(port), "response": bad_https_response, "subdomain": '{0}'.format(subdomain)})
					break
		
		# Test with https for subdomains that don't redirect http
		if not unicode_error:
			for port in ['443', '8443']:
				for number_retries in range(retries):
					try:
						request = requests.get('https://{0}:{1}'.format(subdomain, port), timeout=timeout, verify=False)
						try:
							if request.status_code not in range(400,499) or request.status_code == 404:
								request.raise_for_status() # returns HTTPError if an unsuccessful status code is returned
							https_response = str(request.status_code)
							if len(subdomain) > 80:
								if port not in range(400,499):
									print('{0:^80.80}{3}|{4}{1:^80.80}\n{3}{2}{4}'.format('https://' + subdomain + ":" + port + " " + colors.GREEN + 
										' [' + https_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
								else:
									print('{0:^80.80}{3}|{4}{1:^80.80}\n{3}{2}{4}'.format('https://' + subdomain + ":" + port + " " + colors.GREEN + 
										' [' + https_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
							else:
								if port not in range(400,499):
									print('{0:^80.80}{3}|{4}{1:^80.80}\n{3}{2}{4}'.format('https://' + subdomain + ":" + port + " " + colors.GREEN + 
										' [' + https_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
								else:
									print('{0:^80.80}{3}|{4}{1:^80.80}\n{3}{2}{4}'.format('https://' + subdomain + ":" + port + " " + colors.GREEN + 
										' [' + https_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
	
							live_subdomains["https_responses"].append({"port": '{0}'.format(port), "response": https_response, "subdomain": '{0}'.format(subdomain)})
							break
						except requests.exceptions.HTTPError:
							bad_https_response = str(request.status_code)
							if len(subdomain) > 80:
								print('{1:^80.80}{3}|{4}{0:^80.80}\n{3}{2}{4}'.format('https://' + subdomain + ":" + port + colors.RED + 
									' [' + bad_https_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
							else:
								print('{1:^80.80}{3}|{4}{0:^89.80}\n{3}{2}{4}'.format('https://' + subdomain + ":" + port + colors.RED + 
									' [' + bad_https_response + ']' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
	
							down_subdomains["https_responses"].append({"port": '{0}'.format(port), "response": bad_https_response, "subdomain": '{0}'.format(subdomain)})
							break
					except requests.exceptions.Timeout:
						if number_retries + 1 == retries:
							bad_https_response = 'Timed Out'
							if verbose:
								if len(subdomain) > 80:
									print('{1:^80.80}{3}|{4}{0:^80.80}\n{3}{2}{4}'.format('https://' + subdomain + ":" + port + colors.RED + 
										' [TIMED OUT]' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
								else:
									print('{1:^80.80}{3}|{4}{0:^89.80}\n{3}{2}{4}'.format('https://' + subdomain + ":" + port + colors.RED + 
										' [TIMED OUT]' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
	
							down_subdomains["https_responses"].append({"port": '{0}'.format(port), "response": bad_https_response, "subdomain": '{0}'.format(subdomain)})
						else:
							continue
					except requests.exceptions.ConnectionError:
						bad_https_response = 'Connection Error'
						if verbose:
							if len(subdomain) > 80:
								print('{1:^80.80}{3}|{4}{0:^80.80}\n{3}{2}{4}'.format('https://' + subdomain + ":" + port + colors.RED + 
									' [CONNECTION ERROR]' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
							else:
								print('{1:^80.80}{3}|{4}{0:^89.80}\n{3}{2}{4}'.format('https://' + subdomain + ":" + port + colors.RED + 
									' [CONNECTION ERROR]' + colors.RESET, '', '-' * 160, colors.BLUE, colors.RESET))
	
						down_subdomains["https_responses"].append({"port": '{0}'.format(port), "response": bad_https_response, "subdomain": '{0}'.format(subdomain)})
						break
	
	live = 	[live_http["subdomain"] for live_http in live_subdomains["http_responses"]] + [live_https["subdomain"] for live_https in live_subdomains["https_responses"]]
	with open(subdomains_live_file, 'w') as write_subdomains_live_file:
		write_subdomains_live_file.write('\n'.join(sorted(set(live))))
		write_subdomains_live_file.write('\n')
	
	json_live_path = os.path.join(output_directory, 'web_subdomains.live.json')
	json_down_path = os.path.join(output_directory, 'web_subdomains.down.json')
	if not os.path.isdir(output_directory):
		os.makedirs(output_directory, exist_ok=True)
	with open(json_live_path, 'w') as write_json_live:
		json.dump(live_subdomains, write_json_live, sort_keys=True, indent=4)
	with open(json_down_path, 'w') as write_json_down:
		json.dump(down_subdomains, write_json_down, sort_keys=True, indent=4)
	
	live_count = len(live_subdomains["http_responses"]) + len(live_subdomains["https_responses"])
	down_count = len(down_subdomains["http_responses"]) + len(down_subdomains["https_responses"])
	print('\n{1}[+] LIVE: {0}{2:<9}'.format(colors.RESET, colors.GREEN, live_count))
	print('{1}[+] DOWN: {0}{2:<9}'.format(colors.RESET, colors.RED, down_count))
