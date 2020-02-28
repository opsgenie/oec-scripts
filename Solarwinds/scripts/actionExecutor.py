import argparse
import json
import logging
import sys
import time

import requests
from requests.auth import HTTPBasicAuth

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--payload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Level of log', required=True)
parser.add_argument('-url', '--url', help='Your solarwinds server IP or FQDN', required=False)
parser.add_argument('-login', '--login', help='Name of Solarwinds user that can acknowledge alerts', required=False)
parser.add_argument('-password', '--password', help='Password for Solarwinds user that can acknowledge alerts',
                    required=False)
parser.add_argument('-timeout', '--timeout', help='Timeout', required=False)

args = vars(parser.parse_args())

logging.basicConfig(stream=sys.stdout, level=args['logLevel'])

queue_message_string = args['payload']
queue_message = json.loads(queue_message_string)
logging.debug(queue_message)


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


def acknowledge_solarwinds_alert(url, auth_token, object_id, comment):
    endpoint = url + "/SolarWinds/InformationService/v3/Json/Invoke/Orion.AlertActive/Acknowledge"

    content_array = [[object_id], comment]
    content = json.dumps(content_array)

    logging.warning("Acknowledgement details: " + content)

    response = requests.post(endpoint, data=content, headers={"Content-Type": "application/json"}, auth=auth_token,
                             timeout=timeout)

    if response.status_code < 299:
        logging.info(LOG_PREFIX + " Successfully executed at Solarwinds.")
        logging.debug(LOG_PREFIX + " Solarwinds response: " + str(response.status_code) + " " + str(response.content))
    else:
        logging.warning(LOG_PREFIX + " Could not execute at Solarwinds; response: " + str(response.content)
                        + " status code: " + str(response.status_code))


def close_solarwinds_alert(url, auth_token, object_id, comment):
    endpoint = url + "/SolarWinds/InformationService/v3/Json/Invoke/Orion.AlertActive/ClearAlert"

    content_array = [[object_id]]
    content = json.dumps(content_array)

    logging.warning("Close details: " + content)

    response = requests.post(endpoint, data=content, headers={"Content-Type": "application/json"}, auth=auth_token,
                             timeout=timeout)

    if response.status_code < 299:
        logging.info(LOG_PREFIX + " Successfully executed at Solarwinds.")
        logging.debug(LOG_PREFIX + " Solarwinds response: " + str(response.status_code) + " " + str(response.content))
    else:
        logging.warning(LOG_PREFIX + " Could not execute at Solarwinds; response: " + str(response.content)
                        + " status code: " + str(response.status_code))

    add_note_solarwinds_alert(url, auth_token, object_id, comment)


def add_note_solarwinds_alert(url, auth_token, object_id, comment):
    endpoint = url + "/SolarWinds/InformationService/v3/Json/Invoke/Orion.AlertActive/AppendNote"

    content_array = [[object_id], comment]
    content = json.dumps(content_array)

    logging.warning("Close details: " + content)

    response = requests.post(endpoint, data=content, headers={"Content-Type": "application/json"}, auth=auth_token,
                             timeout=timeout)

    if response.status_code < 299:
        logging.info(LOG_PREFIX + " Successfully executed at Solarwinds.")
        logging.debug(LOG_PREFIX + " Solarwinds response: " + str(response.status_code) + " " + str(response.content))
    else:
        logging.warning(LOG_PREFIX + " Could not execute at Solarwinds; response: " + str(response.content)
                        + " status code: " + str(response.status_code))


def main():
    global LOG_PREFIX
    global timeout

    action = queue_message["action"]
    alert = queue_message["alert"]
    source = queue_message["source"]

    logging.debug("Action: " + str(action))

    LOG_PREFIX = "[" + action + "]:"

    username = parse_field('login', True)
    password = parse_field('password', True)
    url = parse_field('url', True)
    timeout = args['timeout']

    if not timeout:
        timeout = 30000
    else:
        timeout = int(timeout)

    logging.debug("Username: " + username)
    logging.debug("Password: " + password)

    auth_token = HTTPBasicAuth(username, password)

    get_alert_url = args['opsgenieUrl'] + "/v2/alerts/" + alert["alertId"]

    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "application/json",
        "Authorization": "GenieKey " + args['apiKey']
    }

    response = requests.get(get_alert_url, None, headers=headers, timeout=timeout)
    content = response.json()

    if "data" in content.keys():
        alert_from_opsgenie = content["data"]
        if source["type"].lower() != "solarwinds":
            definition_id = alert_from_opsgenie["details"]["AlertDefinitionID"]
            logging.debug("alertDefinitionID: " + str(definition_id))
            object_type = alert_from_opsgenie["details"]["ObjectType"]
            logging.debug("objectType: " + str(object_type))
            object_id = alert_from_opsgenie["details"]["ObjectID"]
            logging.debug("objectID: " + str(object_id))

            str_updated = time.strftime("%m/%d/%Y, %H:%M:%S")
            alert_username = str(alert.get("username"))
            alert_note = str(alert.get("note"))
            alert_message = str(alert.get("message"))
            if action == "Acknowledge":
                message = alert_username + " acknowledged alert: \"" + alert_note + "\" on alert: \"" + \
                          alert_message + "\""
                comment = str_updated + " Acknowledged in Opsgenie by " + alert_username
                acknowledge_solarwinds_alert(url, auth_token, object_id, comment)

            elif action == "AddNote":
                message = alert_username + " added note to alert: \"" + alert_note + "\" on alert: \"" + \
                          alert[
                              "message"] + "\""
                comment = str_updated + " Updated by " + alert_username + " from OpsGenie: " + alert_note
                add_note_solarwinds_alert(url, auth_token, object_id, comment)

            elif action == "Close":
                message = alert_username + " closed alert: \"" + alert_note + "\" on alert: \"" + alert_message + "\""
                comment = str_updated + " Updated by " + alert_username + " from OpsGenie: " + alert_note
                close_solarwinds_alert(url, auth_token, object_id, comment)
            else:
                message = alert_username + " executed [" + action + "] action on alert: \"" + alert_message + "\""

            logging.info(LOG_PREFIX + " " + message)

        else:
            logging.warning(LOG_PREFIX + " Action source is Solarwinds; discarding action in order to prevent looping.")

    else:
        logging.warning(
            LOG_PREFIX + " Alert with id " + alert["alertId"] + " does not exist in Opsgenie. It is probably deleted.")


if __name__ == '__main__':
    main()
