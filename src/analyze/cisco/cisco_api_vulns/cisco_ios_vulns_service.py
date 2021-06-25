import requests
import json
import os
from tqdm import tqdm

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


def get_cisco_ios_vulns_data(version: str, client_id: str, client_secret: str, disable_api: bool) -> json:  # noqa: E501
    if (disable_api):
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
