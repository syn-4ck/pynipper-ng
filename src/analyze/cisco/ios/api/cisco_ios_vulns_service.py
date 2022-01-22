import requests
import array
import configparser
import json
import os
from tqdm import tqdm

from .....error.cisco_errors import GenericCiscoError

from ..api.cisco_vuln import CiscoVuln

ACCESS_URI = "https://cloudsso.cisco.com/as/token.oauth2?client_id="
API_URI = "https://api.cisco.com/security/advisories/ios?version="

API_DATA_FILENAME = "api-data.dat"


def _get_access_token(client_id: str, client_secret: str) -> str:
    headers = {}
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    url = ACCESS_URI + client_id + "&client_secret=" + \
        client_secret + "&grant_type=client_credentials"
    response = requests.post(url, headers=headers)
    data = response.json()
    return data['access_token']


def _get_cisco_ios_vulns_data(version: str, client_id: str, client_secret: str, enable_api: bool) -> json:  # noqa: E501
    if (not enable_api):
        print("[2/4] Cisco API disable.")
        return json.dumps({})
    if (client_id == "" or client_secret == ""):
        print("[2/4] No Cisco API Credentials. Skipping get API data...")
        return json.dumps({})
    access_token = _get_access_token(client_id, client_secret)
    headers = {}
    headers["Authorization"] = 'Bearer ' + access_token
    url = API_URI + version
    response = requests.get(url, headers=headers, stream=True)

    # Implement a progress bar
    print("[2/4] Connecting and getting data from Cisco API")
    total_size_in_bytes = int(response.headers.get('content-length', 0))
    block_size = 1024
    progress_bar = tqdm(total=total_size_in_bytes,
                        unit_divisor=1024, unit='B',
                        unit_scale=True, leave=True)
    f = open(API_DATA_FILENAME, 'wb')
    for data in response.iter_content(block_size):
        progress_bar.update(len(data))
        f.write(data)
    progress_bar.close()
    f.close()

    readable_file = open(API_DATA_FILENAME, 'r')
    file_data = readable_file.read()
    readable_file.close()
    os.remove(API_DATA_FILENAME)
    return json.loads(file_data)

def _vulns_get_fields(vulns: str) -> array:
    vulns_array = []
    try:
        if vulns != '{}':
            for vuln in vulns["advisories"]:
                v = CiscoVuln(
                    vuln["advisoryTitle"],
                    vuln["summary"],
                    vuln["cves"],
                    vuln["cvssBaseScore"],
                    vuln["publicationUrl"]
                )
                vulns_array.append(v)
    except KeyError:
        try:
            if vulns["errorCode"]:
                raise GenericCiscoError(vulns["errorMessage"])
        except KeyError:
            raise GenericCiscoError(
                "Unexpected error getting vulns from Cisco API"
            )
    except Exception:
        raise GenericCiscoError(
            "Unexpected error getting vulns from Cisco API"
        )

    return vulns_array

def get_api_vulnerabilities(configuration, version_cisco_device, online):
    config_file = configparser.ConfigParser()
    config_file.read(configuration)
    client_id = ""
    if config_file.has_option('Cisco', 'CLIENT_ID'):
        client_id = config_file['Cisco']['CLIENT_ID']
    client_secret = ""
    if config_file.has_option('Cisco', 'CLIENT_SECRET'):
        client_secret = config_file['Cisco']['CLIENT_SECRET']

    vulns = _get_cisco_ios_vulns_data(
        version_cisco_device, client_id, client_secret, online)
    vulns_array = _vulns_get_fields(vulns)
    return sorted(vulns_array, reverse=True)
