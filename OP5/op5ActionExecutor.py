import argparse
import json
import logging
import sys

import requests
from requests.auth import HTTPBasicAuth

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Log Level', required=True)
parser.add_argument('-username', '--username', help='Username', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
parser.add_argument('-url', '--url', help='Url', required=False)
args = vars(parser.parse_args())

logging.basicConfig(stream=sys.stdout, level=args['logLevel'])


def parse_field(key, mandatory):
    variable = queue_message.get(key)
    if not variable:
        variable = args.get(key)
    if mandatory and not variable:
        logging.error(LOG_PREFIX + " Skipping action, Mandatory conf item '" + str(key) +
                      "' is missing. Check your configuration file.")
        raise ValueError(LOG_PREFIX + " Skipping action, Mandatory conf item '" + str(key) +
                         "' is missing. Check your configuration file.")
    return variable


def parse_timeout():
    parsed_timeout = args.get('http.timeout')
    if not parsed_timeout:
        return 30000
    return int(parsed_timeout)


def post_to_op5(post_params, typeOfNotification):
    url = parse_field("url", True) + "/api/command/"
    if typeOfNotification == "service":
        url += "ACKNOWLEDGE_SVC_PROBLEM"
    elif typeOfNotification == "host":
        url += "ACKNOWLEDGE_HOST_PROBLEM"

    username = parse_field("username", True)
    password = parse_field("password", True)
    logging.debug("Username: " + str(username))

    token = HTTPBasicAuth(username, password)

    logging.debug(LOG_PREFIX + " Posting to OP5. Url: " + str(url) + " params: " + str(post_params))
    response = requests.post(url, data=json.dumps(post_params), auth=token, timeout=parse_timeout())
    if response and response.status_code == 200:
        logging.info(LOG_PREFIX + " Successfully executed at OP5.")
        logging.debug(LOG_PREFIX + " OP5 response: " + str(response.content))
    else:
        logging.error(
            LOG_PREFIX + " Could not execute at OP5. StatusCode: " + str(response.status_code) + " Response: " + str(
                response.content))


def main():
    global LOG_PREFIX
    global queue_message

    queue_message_string = args['queuePayload']
    queue_message = json.loads(queue_message_string)

    alert_id = queue_message["alert"]["alertId"]
    mapped_action = queue_message["mappedActionV2"]["name"]

    LOG_PREFIX = "[" + mapped_action + "]"
    logging.info("Will execute " + str(mapped_action) + " for alertId " + str(alert_id))

    post_params = {
        "host_name": queue_message.get("host_name"),
        "sticky": queue_message.get("sticky"),
        "notify": queue_message.get("notify"),
        "persistent": queue_message.get("persistent"),
        "comment": queue_message.get("comment")
    }

    service = queue_message.get("service_desc")
    if service:
        post_params.update({"service_description": service})
        post_to_op5(post_params, "service")
    else:
        post_to_op5(post_params, "host")

if __name__ == '__main__':
    main()
