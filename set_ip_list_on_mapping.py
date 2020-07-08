#!/usr/bin/env python3
# coding=utf-8

# Version 1.0

# Example usage
# ./set_ip_list_on_mapping.py -n airlock.ergon.ch -l ^mapping_a$ -i ^IP-list99$

# configure the API key here
API_KEY_FILE="./api_key"
#######################################################################################

import urllib
import ssl
import json
import os
import sys
import re
from argparse import ArgumentParser
from http.cookiejar import CookieJar

parser = ArgumentParser()
parser.add_argument("-n", dest="host", metavar="hostname", required=True,
        help="Airlock Gateway hostname")
group_selector = parser.add_mutually_exclusive_group(required=True)
group_selector.add_argument("-m", dest="mapping_selector_pattern", metavar="pattern",
        help="Pattern matching mapping name") 
group_selector.add_argument("-l", dest="mapping_selector_label", metavar="label",
        help="Label for mapping selection")
parser.add_argument("-i", dest="iplist", metavar="ip list", required=True,
        help="Name of IP list")
group_type = parser.add_mutually_exclusive_group(required=True)
group_type.add_argument("-b", dest="blacklist", action="store_true",
        help="Modify blacklist")
group_type.add_argument("-w", dest="blacklist", action="store_false",
        help="Modify whitelist")
parser.add_argument("-c", dest="confirm", action="store_false",
        help="Non interative mode - no confirmation needed")

args = parser.parse_args()

TARGET_GATEWAY="https://{}".format(args.host)

api_key = open(API_KEY_FILE, 'r').read().strip()
DEFAULT_HEADERS = { 	"Accept": "application/json",
                        "Content-Type": "application/json",
                        "Authorization": "Bearer {}".format(api_key) }

# we need a cookie store
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))

# only necessary if you have configured an invalid SSL cert on the management interface
if (not os.environ.get('PYTHONHTTPSVERIFY', '') and getattr(ssl, '_create_unverified_context', None)):
    ssl._create_default_https_context = ssl._create_unverified_context

# method to send REST calls
def send_request(method, path, body=""):
	req = urllib.request.Request(TARGET_GATEWAY + "/airlock/rest/" + path, body.encode('utf-8'), DEFAULT_HEADERS)
	req.get_method = lambda: method
	r = opener.open(req)
	return r.read()

# create session
send_request("POST", "session/create")

# get current active config id
resp = json.loads(send_request("GET", "configuration/configurations"))
id =  [x["id"] for x in resp["data"] if(x['attributes']["configType"] == "CURRENTLY_ACTIVE")][0]

# load active config
send_request("POST", "configuration/configurations/{}/load".format(id))

# get all mappings
resp = json.loads(send_request("GET", "configuration/mappings"))

# filter mappings
mapping_ids = (
		[ x['id'] for x in resp['data'] if(re.match(args.mapping_selector_pattern, x['attributes']['name'])) ]
		if args.mapping_selector_pattern
		else [ x['id'] for x in resp['data'] if(args.mapping_selector_label in x['attributes']['labels']) ] )
mapping_names = [x['attributes']['name'] for x in resp['data'] if(x['id'] in mapping_ids)]

if not mapping_ids:
	sys.exit("No mapping found - exit")

# get all ip lists
resp = json.loads(send_request("GET", "configuration/ip-address-lists"))

# filter ip lists
ip_list_ids = [ x['id'] for x in resp['data'] if(re.match(args.iplist, x['attributes']['name'])) ]
ip_list_names = [x['attributes']['name'] for x in resp['data'] if(x['id'] in ip_list_ids)]

if not ip_list_ids:
	sys.exit("IP list matching '{}' not found".format(args.iplist))
else:
	ip_list_id = ip_list_ids[0]

# patch the config
for mapping_id in mapping_ids:
	for ip_list_id in ip_list_ids:
		resp = json.loads(send_request("GET", "/configuration/mappings/{}".format(mapping_id)))
		list_type = "blacklists" if args.blacklist else "whitelists"
		current_ip_list_data = (resp['data']['relationships']['ip-address-{}'.format(list_type)]['data']
			if 'ip-address-{}'.format(list_type) in resp['data']['relationships']
			else [])

		data = {
				"data" : [ {
					"id": ip_list_id,
					"type": "ip-address-list"
					} ] + current_ip_list_data
				}

		send_request("PATCH", "configuration/mappings/{}/relationships/ip-address-{}"
			.format(mapping_id, list_type), json.dumps(data))

if args.confirm:
	answer = input('Add {}-group(s) "{}" to mapping(s): {}\nContinue? [y/n] '
			.format(list_type[:-1], ','.join(ip_list_names), '\n\t'.join(sorted(mapping_names))))
	if answer != 'y': sys.exit("Nothing changed")

config_comment = 'REST: {} IP list(s) "{}" added to mapping(s) "{}"' \
			.format(list_type[:-1], ','.join(ip_list_names), ','.join(sorted(mapping_names)))
data = { "comment" : config_comment }

# save config
send_request("POST", "configuration/configurations/save", json.dumps(data))
print('Config saved with comment: {}'.format(config_comment))

# activate config without failover activation!
#send_request("POST", "configuration/configurations/activate", json.dumps(data))

# logout
send_request("POST", "session/terminate")
