#!/usr/bin/env -S uv run

# /// script
# dependencies = [
#     "beautifulsoup4",
#     "requests",
# ]
# ///

import os
import re
import sys

import requests
import bs4

session = requests.Session()

VERIFY_TLS_CERTS = os.getenv("VERIFY_TLS_CERTS") != "false"

url, front_entity_id, api_key, andrvotr_authority_token = sys.argv[1:]
post_data = None

while True:
    print("Requesting", ("POST" if post_data else "GET"), url, *(["with", list(post_data)] if post_data else []))

    if re.match(r'^https://[^/]+/idp/profile/', url):
        idp_host = url.split("/")[2]
        assert post_data is None, post_data
        assert url.startswith("https://" + idp_host + '/idp/profile/SAML2/Redirect/SSO?'), url
        post_data = { 'front_entity_id': front_entity_id, 'api_key': api_key, 'andrvotr_authority_token': andrvotr_authority_token, 'target_url': url }
        url = "https://" + idp_host + "/idp/profile/andrvotr/fabricate"
        print("Nevermind, requesting POST", url, "with", list(post_data))

    response = session.request("POST" if post_data else "GET", url, data=post_data, verify=VERIFY_TLS_CERTS, allow_redirects=False)

    print("Received", response.status_code, response.reason)
    print()

    if 300 <= response.status_code <= 399 and 'location' in response.headers:
        url = response.headers['location']
        post_data = None
        continue

    if response.status_code == 200 and b"document.forms[0].submit()" in response.content:
        soup = bs4.BeautifulSoup(response.text)
        url = soup.form['action']
        post_data = { input['name']: input['value'] for input in soup.find_all('input') if input['type'] == 'hidden' }
        continue

    print("Final headers:", response.headers)
    sys.stdout.buffer.write(b"Final content: [" + response.content + b"]\n")
    break
