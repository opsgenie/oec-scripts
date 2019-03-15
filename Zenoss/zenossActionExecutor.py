import argparse
import json
import logging
import sys

import base64
import requests

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Log Level', required=True)
parser.add_argument('-command_url', '--command_url', help='The url', required=False)
parser.add_argument('-username', '--username', help='Username', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
args = vars(parser.parse_args())

logging.basicConfig(stream=sys.stdout, level=args['logLevel'])


def parse_field(key, mandatory):
    variable = queue_message.get(key)
    if not variable:
        variable = args.get(key)
    if mandatory and not variable:
        logging.error(LOG_PREFIX + " Skipping action, Mandatory conf item '" + key +
                      "' is missing. Check your configuration file.")
        raise ValueError(LOG_PREFIX + " Skipping action, Mandatory conf item '" + key +
                         "' is missing. Check your configuration file.")
    return variable


def parse_timeout():
    parsed_timeout = args.get('http.timeout')
    if not parsed_timeout:
        return 30000
    return int(parsed_timeout)


def main():
    global LOG_PREFIX
    global queue_message

    queue_message_string = args['queuePayload']
    queue_message = json.loads(queue_message_string)

    timeout = parse_timeout()

    alert_id = queue_message["alert"]["alertId"]
    action = queue_message["action"]
    source = queue_message["source"]

    LOG_PREFIX = "[" + action + "]"

    logging.info("Will execute " + str(action) + " for alertId " + str(alert_id))

    username = parse_field('username', True)
    password = parse_field('password', True)
    url = parse_field('command_url', True)

    logging.debug("Username: " + str(username))
    logging.debug("Command Url: " + str(url))
    logging.debug("AlertId: " + str(alert_id))
    logging.debug("Source: " + str(source))
    logging.debug("Action: " + str(action))

    token = base64.b64encode((username + ":" + password).encode('US-ASCII'))
    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "application/json",
        "Authorization": "Basic " + bytes(token).decode("US-ASCII")
    }
    if alert_id:
        opsgenie_alert_api_url = args['opsgenieUrl'] + "/v2/alerts/" + alert_id
        opsgenie_alert_api_headers = {
            "Content-Type": "application/json",
            "Accept-Language": "application/json",
            "Authorization": "GenieKey " + args['apiKey']
        }
        alert_response = requests.get(opsgenie_alert_api_url, headers=opsgenie_alert_api_headers, timeout=timeout)
        if alert_response.status_code < 299 and alert_response.json()['data']:
            post_params = {
                "action": "EventsRouter",
                "data": {
                    "evids": [alert_response.json()["data"]["alias"]]
                },
                "type": "rpc",
                "tid": alert_id
            }
            discard_action = False
            if action == "Acknowledge":
                if source and str(source['name']).lower() == "zenoss":
                    logging.warning("Opsgenie alert is already acknowledged by zenoss. Discarding!!!")
                    discard_action = True
                else:
                    post_params.update({"method": "acknowledge"})
            elif action == "Close":
                if source and str(source['name']).lower() == "zenoss":
                    logging.warning("Opsgenie alert is already closed by zenoss. Discarding!!!")
                    discard_action = True
                else:
                    post_params.update({"method": "close"})

            if not discard_action:
                logging.debug("Posting to Zenoss. Command Url: " + str(url) + ", params: " + str(post_params))
                response = requests.post(url, data=json.dumps(post_params), headers=headers, timeout=timeout)
                if response.status_code == 200:
                    logging.info("Successfully executed at Zenoss.")
                    logging.debug("Zenoss response: " + str(response.content))
                else:
                    logging.warning(
                        "Could not execute at Zenoss. Zenoss Response: " + str(response.content) + " Status Code: " + str(response.status_code))
        else:
            logging.warning("Alert with id [" + str(alert_id) + "] does not exist in OpsGenie. It is probably deleted.")
    else:
        logging.warning("Alert id does not exist ")


if __name__ == '__main__':
    main()
