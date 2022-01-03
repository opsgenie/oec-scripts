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
parser.add_argument('-command_url', '--command_url', help='The Command URL', required=False)
parser.add_argument('-user', '--user', help='User', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
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


def login_to_zabbix(user, password, url):
    login_params = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "user": user,
            "password": password
        },
        "id": 1
    }
    logging.debug(LOG_PREFIX + " Logging in to Zabbix. Url: " + str(url) + " user: " + str(user))
    content_headers = {
        "Content-Type": "application/json"
    }
    login_result = requests.post(url, data=json.dumps(login_params), headers=content_headers, timeout=timeout)
    logging.debug(LOG_PREFIX + " login response: " + str(login_result.status_code) + " " + str(login_result.json()))
    if login_result.json() and not login_result.json().get('error'):
        return login_result.json()['result']
    else:
        logging.error(
            LOG_PREFIX + " Cannot login to Zabbix: Response " + str(login_result.status_code) + " " + str(login_result.content))


def main():
    global LOG_PREFIX
    global queue_message
    global timeout

    queue_message_string = args['queuePayload']
    queue_message = json.loads(queue_message_string)

    alert_id = queue_message["alert"]["alertId"]
    action = queue_message["action"]
    source = queue_message["source"]

    LOG_PREFIX = "[" + action + "]"

    timeout = parse_timeout()

    logging.info("Will execute " + str(action) + " for alertId " + str(alert_id))

    username = parse_field('user', True)
    password = parse_field('password', True)
    url = parse_field('command_url', True)

    logging.debug("Username: " + str(username))
    logging.debug("Command Url: " + str(url))
    logging.debug("AlertId: " + str(alert_id))
    logging.debug("Source: " + str(source))
    logging.debug("Action: " + str(action))

    if alert_id:
        alert_api_url = args['opsgenieUrl'] + "/v2/alerts/" + alert_id
        headers = {
            "Content-Type": "application/json",
            "Accept-Language": "application/json",
            "Authorization": "GenieKey " + args['apiKey']
        }
        alert_response = requests.get(alert_api_url, headers=headers, timeout=timeout)
        if alert_response.status_code < 299 and alert_response.json()['data']:
            if action == "Acknowledge":
                if source and str(source['name']).lower() == "zabbix":
                    logging.warning("OpsGenie alert is already acknowledged by Zabbix. Discarding!!!")
                else:
                    post_params = {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "event.acknowledge",
                        "params": {
                            "eventids": queue_message["alert"]["details"]["eventId"],
                            "message": "Acknowledged by " + alert_response.json()['data']['report'][
                                'acknowledgedBy'] + " via Opsgenie",
                            "action": 6
                        }
                    }
                    auth = login_to_zabbix(username, password, url)
                    if auth:
                        logging.debug("Posting to Zabbix.  Url: " + str(url) + ", params: " + str(post_params))
                        post_params.update({"auth": auth})
                        headers = {
                            "Content-Type": "application/json",
                        }
                        response = requests.post(url, data=json.dumps(post_params), headers=headers, timeout=timeout)
                        if alert_response.json() and not alert_response.json().get('error'):
                            logging.info("Successfully executed at Zabbix.")
                            logging.debug("Zabbix response: " + str(response.json()))
                        else:
                            logging.warning(
                                "Could not execute at Zabbix. Zabbix Response: " + response.content + " Status Code: " + response.status_code)
                    else:
                        logging.warning(LOG_PREFIX + "Cannot login to Zabbix!")
        else:
            logging.warning("Alert with id [" + str(alert_id) + "] does not exist in Opsgenie. It is probably deleted.")
    else:
        logging.warning("Alert id does not exist ")


if __name__ == '__main__':
    main()
