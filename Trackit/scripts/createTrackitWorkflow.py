import argparse
import json
import logging
import sys

import requests

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Log level', required=True)
parser.add_argument('-url', '--url', help='The url', required=False)
parser.add_argument('-login', '--login', help='Login', required=False)
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


def login_to_trackit(url):
    final_url = url + "/TrackitWeb/api/login?username=" + parse_field("login",
                                                                      True) + "&pwd=" + parse_field(
        "password", True)
    logging.debug("Url: " + final_url)
    response = requests.get(final_url, timeout)
    if response:
        response_map = response.json()
        if response_map:
            return response_map['data']['apiKey']

    return None


def main():
    global LOG_PREFIX
    global queue_message
    global timeout

    queue_message_string = args['queuePayload']
    queue_message = json.loads(queue_message_string)
    alert = queue_message["alert"]
    alert_id = alert["alertId"]
    action = queue_message["action"]

    LOG_PREFIX = "[" + action + "]"
    logging.info("Will execute " + action + " for alertId " + alert_id)

    timeout = parse_timeout()
    url = parse_field("url", True)
    track_key = login_to_trackit(url)

    if action == "Create":
        headers = {
            "Content-Type": "text/json",
            "Accept": "text/json",
            "TrackitAPIKey": track_key
        }
        content_params = {
            "StatusName": "Open",
            "Summary": alert['message'],
            "RequestorName": parse_field("login", True)
        }
        create_url = str(url) + "/TrackitWeb/api/workorder/Create"
        logging.debug(
            "Before Post -> Url: " + create_url + ", " + "Request Headers: " + str(headers) + " Content: " + str(content_params))
        response = requests.post(create_url, json.dumps(content_params), headers=headers, timeout=timeout)
        if response.status_code < 299:
            logging.info(LOG_PREFIX + " Successfully executed at TrackIt.")
            try:
                response_map = response.json()
                if response_map:
                    flow_id = response_map['data']['data']['Id']
                    if flow_id:
                        alert_api_url = args['opsgenieUrl'] + "/v2/alerts/" + alert_id + "/details"
                        content = {
                            "details":
                                {
                                    "workflow_id": flow_id
                                }
                        }
                        headers = {
                            "Content-Type": "application/json",
                            "Accept-Language": "application/json",
                            "Authorization": "GenieKey " + args['apiKey']
                        }
                        alert_response = requests.post(alert_api_url,
                                                       data=json.dumps(content), headers=headers, timeout=timeout)
                        if alert_response.status_code < 299:
                            logging.info(LOG_PREFIX + " Successfully sent to Opsgenie")
                            logging.debug(
                                LOG_PREFIX + " TrackIt response: " + str(alert_response.content) + " " + str(alert_response.status_code))
                        else:
                            logging.warning(
                                LOG_PREFIX + " Could not execute at Opsgenie; response: " + str(alert_response.content) + " status code: " + str(alert_response.status_code))
                    else:
                        logging.warning(
                            LOG_PREFIX + " Flow Id does not exist.")
            except ValueError:
                logging.error(
                    LOG_PREFIX + " Response does not have flow Id variable, " + str(response.content) + " " + str(response.status_code))
        else:
            logging.warning(
                LOG_PREFIX + " Could not execute at TrackIt; response: " + str(response.content) + " " + str(response.status_code))


if __name__ == '__main__':
    main()
