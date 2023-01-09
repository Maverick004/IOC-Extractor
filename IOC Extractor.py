import json
import re
import time
import urllib.request as urllib
import requests

# Fetch IOC data
IOC_LIST_LINK = 'https://hrcdn.net/s3_pub/istreet-assets/_CMVZc6AbxXpRZCXCS9yRA/input000.txt'
IOC_LIST_DATA = urllib.urlopen(IOC_LIST_LINK).read().decode('UTF-8')

# Gets all IPs from text file
IPs = re.findall(r'[0-9]+(?:\.[0-9]+){3}', IOC_LIST_DATA)

# Filters duplicated IP addresses
filtered_list = list(dict.fromkeys(IPs))

# VirusTotal request setup
API_KEY = 'addc7f64b088413655b51c677e755d557cb29c7724db2bb83fed1d4984d70e5f'
url = 'https://www.virustotal.com/vtapi/v2/url/report'

# Results indicator
results = { "indicators": [] }

# Loops through filtered IPs and fetches records from VirusTotal
for i in filtered_list[:2]:
    # Requests data from virus_total
    parameters = {'apikey': API_KEY, 'resource': i}
    response= requests.get(url, params=parameters)
    data = response.json()

    # Data for a particular IP address
    ip_data = {};
    ip_data["value"] = i
    ip_data["type"] = "ip"

    # Provider list
    virus_total_data = {}
    virus_total_data["provider"] = "VirusTotal"
    virus_total_data["verdict"] = "clean"

    # checks for malicious verdicts
    if data["positives"] > 0:
        virus_total_data["verdict"] = "malicious"

    virus_total_data["score"] = "{}/{}".format(data["positives"], data["total"])
  
    ip_data["providers"] = []
    ip_data["providers"].append(virus_total_data)

    results["indicators"].append(ip_data)

    # Virus api request rate limit is 4 req/min
    # time.sleep(15)

print(json.dumps(results, indent = 2))


############### THANK YOU, THIS WAS QUITE INSIGHTFUL AND INTERESTING ###############