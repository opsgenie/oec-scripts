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
parser.add_argument('-loglevel', '--loglevel', help='Log level', required=True)
parser.add_argument('-host', '--host', help='The host', required=False)
parser.add_argument('-port', '--port', help='The port', required=False)
parser.add_argument('-username', '--username', help='Username', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
parser.add_argument('-url', '--url', help='Url', required=False)
args = vars(parser.parse_args())

logging.basicConfig(stream=sys.stdout, level=args['loglevel'])


def parse_field(key, mandatory):
    variable = queue_message[key]
    if not variable.strip():
        variable = args[key]
    if mandatory and not variable:
        logging.error(LOG_PREFIX + " Skipping action, Mandatory conf item '" + key +
                      "' is missing. Check your configuration file.")
        raise ValueError(LOG_PREFIX + " Skipping action, Mandatory conf item '" + key +
                         "' is missing. Check your configuration file.")
    return variable


def parse_timeout():
    parsed_timeout = args['http.timeout']
    if not parsed_timeout:
        return 30000
    return int(parsed_timeout)


def main():
    global LOG_PREFIX
    global URL_SUFFIX
    global queue_message

    URL_SUFFIX = "ACKNOWLEDGE_HOST_PROBLEM"

    queue_message_string = args['queuePayload']
    queue_message = json.loads(queue_message_string)

    alert_id = queue_message["alert"]["alertId"]
    action = queue_message["action"]
    source = queue_message["source"]

    timeout = parse_timeout()

    LOG_PREFIX = "[" + action + "]"

    logging.info("Will execute " + action + " for alertId " + alert_id)

    sticky = 0
    notify = False
    persistent = False
    protocol = "https"

    username = parse_field('username', True)
    password = parse_field('password', True)
    token = base64.b64encode((username + ":" + password).encode('US-ASCII'))
    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "application/json",
        "Authorization": "Basic " + str(token)
    }
    if alert_id:
        alert_api_url = args['opsgenieUrl'] + "/" + alert_id
        alert_api_headers = {
            "Content-Type": "application/json",
            "Accept-Language": "application/json",
            "Authorization": "GenieKey " + args['apiKey']
        }
        alert_response = requests.get(alert_api_url, headers=alert_api_headers, timeout=timeout)
        if alert_response.status_code < 299:
            if alert_response.json()['data']:
                host_name = alert_response.json()['data']['details']['host_name']
                service = alert_response.json()['data']['details']['service_desc']
                discard_action = False

                post_params = {
                    "sticky": sticky,
                    "notify": notify,
                    "persistent": persistent,
                    "host_name": host_name
                }

                if action == "Acknowledge":
                    if source and str(source['name']).lower().startswith("nagios"):
                        logging.warning(LOG_PREFIX + " Opsgenie alert is already acknowledged by OP5. Discarding...")
                        discard_action = True
                    else:
                        if service:
                            URL_SUFFIX = "ACKNOWLEDGE_SVC_PROBLEM"
                            post_params.update({"comment": "Acknowledged by " + alert_response.json()['data']['report'][
                                'acknowledgedBy'] + " via OpsGenie"})

                if not discard_action:
                    host = parse_field('host', True)
                    port = parse_field('port', False)
                    url = protocol + "://" + host
                    if port:
                        url += ":" + port
                    url += "/api/command/" + URL_SUFFIX
                    logging.debug(LOG_PREFIX + " Posting to OP5. Url: " + str(url) + ", params: " + str(post_params))
                    response = requests.post(url, data=json.dumps(post_params), headers=headers, timeout=timeout)
                    if response.status_code == 200:
                        logging.info(LOG_PREFIX + " Successfully executed at Op5.")
                        logging.debug(LOG_PREFIX + " Op5 response: " + str(response.text))
                    else:
                        logging.warning(
                            LOG_PREFIX + " Could not execute at OP5. OP5 Response: " + response.text + " Status Code: " + response.status_code)
            else:
                logging.warning(
                    LOG_PREFIX + " Alert with id [" + alert_id + "] does not exist in Opsgenie. It is probably deleted.")
    else:
        logging.warning(LOG_PREFIX + " Alert id does not exist ")


if __name__ == '__main__':
    main()
