import json
import requests
import time
from datetime import datetime
from datetime import timedelta
from requests.exceptions import HTTPError
import argparse


def main():
    dt = datetime.now() + timedelta(days=30)
    parser = argparse.ArgumentParser(description='Globally Unique Identifier API')
    parser.add_argument('-g', '--guid', type=str, help='Globally Unique Identifier')
    parser.add_argument('-e', '--expire', type=str, help='GUID expire date (Y-M-D)', default=dt)
    parser.add_argument('-u', '--user', type=str, help='User Name')
    parser.add_argument('-o', '--operation', type=str, help='CRUD operations (Create, Read, Update, Delete)')
    args = parser.parse_args()

    if args.operation == "create":
        create_guid(args.user, args.expire, args.guid)
    elif args.operation == "read":
        get_guid(args.guid)
    elif args.operation == "update":
        update_guid(args.guid, args.expire)
    elif args.operation == "delete":
        delete_guid(args.guid)


'''
Test Case 1:  POST 
Endpoint: "https://127.0.0.1:5000/guid/" + GUID
Payload: 32 chars GUID, expire, user
Expire time: convert into Unix time
Response expected status code: 201
Response expected body: guid, expire, user
Validate: Response code 201, body fields: guid, expire and user

Test Case 2: POST: 
Endpoint: "https://127.0.0.1:5000/guid/" 
Expire time: Default time in unix (current time + 30 days)
Payload: user
GUID: API will generate 32 hexadecimal characters
Response expected status code: 201
Response expected body: guid, expire, user
Validate: Response code 201, body fields: user, GUID and expire not none
'''


def create_guid(req_expire, req_user, req_guid=None):
    url = "https://127.0.0.1:5000/guid/" + req_guid
    dt = time.mktime(req_expire.timetuple())
    timestamp = str(dt).split('.')[0]
    if req_expire is None:
        payload = {"user": req_user}
    else:
        payload = {"expire": timestamp, "user": req_user}

    resp = requests.post(url, data=payload)
    try:
        resp.raise_for_status()
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')

    resp_body = resp.json()

    assert resp.status_code == 201
    if req_guid is None:
        assert resp_body['guid'] is not None
    else:
        assert resp_body['guid'] == req_guid
    assert resp_body['expire'] == timestamp
    assert resp_body['user'] == req_user

    pretty_print_response(resp)


'''
Test Case 3:  GET 
Endpoint: "https://127.0.0.1:5000/guid/" + GUID
Payload: None
Response expected status code: 200
Response expected body: guid, expire, user
Validate: Response code 200, GUID, expire time length not none
'''


def get_guid(req_guid):
    url = "https://127.0.0.1:5000/guid/" + req_guid
    resp = requests.get(url)
    try:
        resp.raise_for_status()
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')

    resp_body = resp.json()

    assert resp.status_code == 200
    assert resp_body['guid'] == req_guid
    assert resp_body['expire'] is not None
    assert resp_body['user'] is not None

    print(pretty_print_response(resp))


'''
Test Case 4:  PUT 
Endpoint: "https://127.0.0.1:5000/guid/" + GUID
Payload: expire
Response expected status code: 201
Response expected body: guid, expire, user
Validate: Response code 201, GUID, Expire, user not None
'''


def update_guid(req_guid, req_expire):
    url = "https://127.0.0.1:5000/guid/" + req_guid
    dt = time.mktime(req_expire.timetuple())
    timestamp = str(dt).split('.')[0]
    payload = {"expire": timestamp}
    resp = requests.put(url, data=payload)
    try:
        resp.raise_for_status()
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')

    resp_body = resp.json()

    assert resp.status_code == 201
    assert resp_body['guid'] == req_guid
    assert resp_body['expire'] == req_expire
    assert resp_body['user'] is not None

    print(pretty_print_response(resp))


'''
Test Case 5:  DELETE 
Endpoint: "https://127.0.0.1:5000/guid/" + GUID
Payload: None
Response expected status code: 200
Response expected body: None
Validate: Response code 200
'''


def delete_guid(req_guid):
    url = "https://127.0.0.1:5000/" + req_guid
    resp = requests.delete(url)
    try:
        resp.raise_for_status()
    except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')
    except Exception as err:
        print(f'Other error occurred: {err}')

    assert resp.status_code == 200


def pretty_print_response(response):
    print('\n{}\n{}\n\n{}\n\n{}\n'.format(
        '<-----------Response-----------',
        'Status code:' + str(response.status_code),
        '\n'.join('{}: {}'.format(k, v) for k, v in response.headers.items()),
        response.text)
    )


if __name__ == '__main__':
    main()



