import urllib.parse
import requests
import pandas as pd
from http import HTTPStatus
import logging
import ujson as json
import os
from retry import retry
config = json.loads(open(os.path.join(os.getcwd(), "azure_config.json"), "rb").read())

LOG = logging.getLogger()


class AdLogsNames(str):
    USERNAME = 'Username'
    TIMESTAMP = 'timestamp'
    DESTINATION = 'destination'
    SOURCE = 'source host'
    AUTH_TYPE = 'auth type'


class SignInNames(str):
    USER = 'userPrincipalName'
    TIMESTAMP = 'createdDateTime'
    DESTINATION = 'resourceDisplayName'
    DEVICE_DETAILS = 'deviceDetail'
    DISPLAY_NAME = 'displayName'
    AUTH_TYPE = 'Cloud'


def convert_sign_in_logs_to_df(signin_response, output_filename='cloud_logs'):
    sign_in_logs = []
    for signin in signin_response:
        device_details = signin.get(SignInNames.DEVICE_DETAILS, {})
        device_display_name = device_details.get(SignInNames.DISPLAY_NAME)
        if device_display_name:
            sign_in_logs.append({
                AdLogsNames.USERNAMWE: signin[SignInNames.USER],
                AdLogsNames.TIMESTAMP: signin[SignInNames.TIMESTAMP],
                AdLogsNames.DESTINATION: signin[SignInNames.DESTINATION],
                AdLogsNames.SOURCE: device_display_name
            })

    sign_in_logs_df = pd.DataFrame(sign_in_logs)
    sign_in_logs_df.to_csv(output_filename)


@retry(Exception, delay=2, tries=3)
def do_azure_request(url, json_data, token):
    headers = {
        'Authorization': 'Bearer {}'.format(token)
    }
    response = None
    try:
        response = requests.get(url, headers=headers, json=json_data)
        if response is None:
            return None

        if response.status_code != HTTPStatus.OK:
            LOG.info(f"Unexpected status code from {url=}: {response.status_code}")
            return None

    except Exception as e:
        LOG.info(f"Error while accessing {url=}: {e=}")

    LOG.info(f"Done getting azure data from the following url: {url=}")
    return response


def get_next_request_url(json_response):
    next_link = json_response.get("@odata.nextLink")
    return urllib.parse.unquote_plus(next_link) if next_link is not None else None


def get_aad_component(token):
    records = []
    url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"

    while url is not None:
        LOG.info(f"Retrieving AAD records by the following URL: {url}")
        response = do_azure_request(url, None, token)
        if response is None:
            LOG.info("Got error in middle of get_aad_component loop")
            return None

        response_content = response.json()
        if "error" in response_content:
            LOG.info(f'Got error from Azure: {response_content}')
            return None

        records += response_content["value"]
        url = get_next_request_url(response_content)

    LOG.info(f"Got {len(records)} records from azure")
    return records


def get_azure_ad_access_token():
    token_r = None
    # Use the redirect URL to create a token url
    token_url = f'https://login.microsoftonline.com/{config["TENANT_ID"]}/oauth2/token'
    token_data = {
        'grant_type': 'password',
        'client_id': config['CLIENT_ID'],
        'client_secret': config['CLIENT_SECRET'],
        'resource': 'https://graph.microsoft.com',
        'scope': 'https://graph.microsoft.com',
        'username': config['USER'],  # Account with no 2MFA
        'password': config['PASSWORD'],
    }
    try:
        token_r = requests.post(token_url, data=token_data)
    except Exception:
        LOG.exception("Got exception while retrieving access tokens:")

    if token_r is None or token_r.status_code != HTTPStatus.OK:
        return None

    return token_r.json().get("access_token")


def main():
    access_token = get_azure_ad_access_token()
    assert access_token is not None, "Failed to retrieve access token."
    sign_in_logs = get_aad_component(access_token)
    assert sign_in_logs is not None, "Failed to retrieve sign-in logs from Azure AD"
    convert_sign_in_logs_to_df(sign_in_logs)


if __name__ == '__main__':
    main()
