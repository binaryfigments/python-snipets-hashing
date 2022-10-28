#!/usr/bin/env python
from http.client import OK
import requests
import json
import hashlib
from pathlib import Path

# Defining the api-endpoint
url = 'https://isc.sans.edu/api/ip/141.98.10.71?json'

artifact_dshield_file = 'dshield_result.json'

headers = {
    'Accept': 'application/json'
}

response = requests.request(method='GET', url=url, headers=headers)

# Formatted output
decoded_response = json.loads(response.text)

with open(artifact_dshield_file, 'w', encoding='utf-8') as fj:
    json.dump(decoded_response, fj, ensure_ascii=False, indent=2)


# Checksum function
def artifact_checksum(file_in):
    """
    This function does something with checksums
    """

    # check if file exists
    path = Path(file_in)

    if path.is_file():
        print(f'The file {file_in} exists')
    else:
        return 'Error'

    # get sha256 hash from file
    hash = hashlib.sha256()
    with open(file_in, 'rb') as file:
        buffer = file.read()
        hash.update(buffer)

    with open(file_in+".sha256sum", 'w') as out:
        out.write(hash.hexdigest() + ' *' + file_in + '\n')
        out.close()

# Checksum verify function


def artifact_verify_checksum(sumfile):
    """
    This function verifies checksums
    """
    try:
        with open(sumfile, 'r') as file:
            first_line = file.readline().rstrip()
    except:
        return False, "Error"

    with open(sumfile, 'r') as file:
        first_line = file.readline().rstrip()

    print(first_line)
    hashinfo = first_line.split(' *')
    print(hashinfo)

    # get sha256 hash from file
    hash = hashlib.sha256()
    with open(hashinfo[1], 'rb') as checkfile:
        buffer = checkfile.read()
        hash.update(buffer)

    if (hashinfo[0] == hash.hexdigest()):
        return True, "NoError"
    else:
        return False, "NoError"


artifact_checksum(artifact_dshield_file)

print(artifact_verify_checksum('dshield_result.json.sha256sum'))
