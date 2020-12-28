import argparse
import json

import requests

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--queuePayload', required=True)
parser.add_argument('-logLevel', '--logLevel', required=True)
parser.add_argument('-apiKey', '--apiKey', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', required=True)
parser.add_argument('-method', '--method', required=False)
parser.add_argument('-url', '--url', required=False)
parser.add_argument('-headers', '--headers', type=json.loads, required=False)
parser.add_argument('-params', '--params', type=json.loads, required=False)
parser.add_argument('-body', '--body', required=False)
args = vars(parser.parse_args())

raw_message = args['queuePayload']
raw_message = raw_message.strip()
message = json.loads(raw_message)


def parse_field(key, mandatory=True):
    variable = args.get(key)
    if not variable:
        variable = message.get(key)
    if not variable and mandatory:
        raise ValueError("Skipping execution [" + key + "] field does not exist in payload and configs.")
    return variable


def main():
    method = parse_field("method")
    url = parse_field("url")
    headers = parse_field("headers", False)
    params = parse_field("params", False)
    body = parse_field("body", False)

    response = requests.request(method=method, url=url, headers=headers,
                                params=params, data=body)

    result = {
        "headers": dict(response.headers),
        "body": response.text,
        "statusCode": response.status_code
    }

    print(json.dumps(result))


if __name__ == '__main__':
    main()
