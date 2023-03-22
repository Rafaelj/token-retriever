import jwt
import pyperclip
import requests
import logging
import argparse
from datetime import datetime


def decode_token(encoded_token, client_secret):
    try:
        algorithm = determine_algorithm(encoded_token)
        return jwt.decode(encoded_token, client_secret, algorithms=[algorithm], 
options={"verify_signature": False})
    except Exception as e:
        print("Error decoding token: {}".format(e))


def determine_algorithm(encoded_token):
    header = jwt.get_unverified_header(encoded_token)
    algorithm = header["alg"]
    print("Using algorithm '{}'to decode token".format(algorithm))
    return algorithm


def get_access_token(response):
    response_data = response.json()
    return response_data.get('access_token')


def copy_to_clipboard(token):
    pyperclip.copy("Bearer {}".format(token))
    print("Token copied to clipboard")


def get_token(token_endpoint, token_request_params):
    # Capture InsecureRequestWarning message to clean up the execution log
    # https://urllib3.readtheodocs.io/en/1.2.6.x/advanced-usage.html#ssl-warnings
    logging.captureWarnings(True)

    response = requests.post(token_endpoint, data=token_request_params)

    # TODO replace by response.raise_for_status()
    #  https://requests.readthedocs.io/en/latest/api/#requests.Response.raise_for_status
    if response.status_code == 200:
        return get_access_token(response)
    else:
        print("Error: ", response.status_code, response.text)


def parse_arguments(arguments):
    parser = argparse.ArgumentParser(description='Description of your script')

    parser.add_argument('url', help='Token url')
    parser.add_argument('-i', '--client', help='Client identification')
    parser.add_argument('-s', '--secret', help='Client secret')
    parser.add_argument('-u', '--username', help='Username')
    parser.add_argument('-p', '--password', help='Password')
    parser.add_argument('-g', '--grant', help='Grant type')
    parser.add_argument('-sc', '--scope', help='Scope')

    return parser.parse_args(arguments)


def verify_expiration(decoded_token):
    expiration_time = decoded_token.get('exp', None)
    if expiration_time is not None:
        if is_expired(expiration_time):
            print("Token has expired")
        else:
            show_expiration(decoded_token)
    else:
        print("Token does not have an expiration time")


def is_expired(expiration_time):
    current_time = datetime.utcnow().timestamp()
    return False if current_time < expiration_time else True


def show_expiration(decoded_token):
    expiration_time = decoded_token["exp"]
    print("Token expiration time: {}".format(expiration_time))


def main(arguments):
    args = parse_arguments(arguments)

    endpoint = args.url
    client_id = args.client_id
    client_secret = args.secret
    username = args.username
    password = args.password
    grant_type = args.grant_type
    scope = args.scope

    request_params = {
        "username": username,
        "password": password,
        "scope": scope,
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": grant_type
    }

    access_token = get_token(endpoint, request_params)

    if access_token is not None:
        decoded_token = decode_token(access_token, client_secret)
        verify_expiration(decoded_token)
        copy_to_clipboard(access_token)
