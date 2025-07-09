import argparse
import json
import logging
import sys

import requests

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Level of log', required=True)
parser.add_argument('-serverUrl', '--serverUrl', help='Solarwinds Server URL', required=True)
parser.add_argument('-apiToken', '--apiToken', help='Api Token', required=True)
parser.add_argument('-httpTimeout', '--httpTimeout', help='Timeout for http requests', required=False)

args = vars(parser.parse_args())

queue_message_string = args['queuePayload']
queue_message = json.loads(queue_message_string)
CLOSE_STATUS_ID = 3
ACKNOWLEDGED_STATUS_ID = 6

logging.basicConfig(stream=sys.stdout, level=args['logLevel'])


def parse_field(key, mandatory):
    variable = queue_message[key]
    if not variable.strip():
        variable = args[key]
    if mandatory and not variable:
        raise ValueError(LOG_PREFIX + " Skipping action, Mandatory conf item '" + key +
                         "' is missing. Check your configuration file.")


def send_close_request():
    alert_alias = queue_message['alert']['alias']
    content_type_header = {"content_type": "application/json"}
    url = SERVER_URL + "/helpdesk/WebObjects/Helpdesk.woa/ra/Tickets/" + alert_alias + "?apiKey=" + API_TOKEN

    status_type = {"id": CLOSE_STATUS_ID}
    content_params = {"statustype": status_type}

    response = requests.put(url, json=content_params, headers=content_type_header, timeout=HTTP_TIMEOUT)
    if response.status_code < 400:
        logging.info(LOG_PREFIX + ' Successfully executed at Solarwinds.')
        logging.debug(LOG_PREFIX + " Solarwinds response:" + str(response.content))
    else:
        logging.error(
            LOG_PREFIX + " Could not execute at Solarwinds; response: " + str(response.status_code) + ' ' + str(
                response.content))


def send_acknowledge_request():
    alert_alias = queue_message['alert']['alias']
    content_type_header = {"content_type": "application/json"}
    url = SERVER_URL + "/helpdesk/WebObjects/Helpdesk.woa/ra/Tickets/" + alert_alias + "?apiKey=" + API_TOKEN

    status_type = {"id": ACKNOWLEDGED_STATUS_ID}
    content_params = {"statustype": status_type}

    response = requests.put(url, json=content_params, headers=content_type_header, timeout=HTTP_TIMEOUT)
    if response.status_code < 400:
        logging.info(LOG_PREFIX + ' Successfully executed at Solarwinds.')
        logging.debug(LOG_PREFIX + " Solarwinds response:" + str(response.content))
    else:
        logging.error(
            LOG_PREFIX + " Could not execute at Solarwinds; response: " + str(response.status_code) + ' ' + str(
                response.content))


def send_add_note_request():
    alert_alias = queue_message['alert']['alias']
    alert_note = queue_message['alert']['note']
    content_type_header = {"content_type": "application/json"}
    url = SERVER_URL + "/helpdesk/WebObjects/Helpdesk.woa/ra/TechNotes?apiKey=" + API_TOKEN

    job = {"type": "JobTicket",
           "id": alert_alias
           }
    content_params = {
        "noteText": alert_note,
        "jobticket": job,
        "workTime": "0",
        "isHidden": False,
        "isSolution": False,
        "emailClient": True,
        "emailTech": True,
        "emailTechGroupLevel": False,
        "emailGroupManager": False,
        "emailCc": False,
        "emailBcc": False,
        "ccAddressesForTech": "",
        "bccAddresses": ""
    }
    response = requests.post(url, json=content_params, headers=content_type_header, timeout=HTTP_TIMEOUT)
    if response.status_code < 400:
        logging.info(LOG_PREFIX + ' Successfully executed at Solarwinds.')
        logging.debug(LOG_PREFIX + " Solarwinds response:" + str(response.content))
    else:
        logging.error(
            LOG_PREFIX + " Could not execute at Solarwinds; response: " + str(response.status_code) + ' ' + str(
                response.content))


def main():
    global LOG_PREFIX
    global SERVER_URL
    global API_TOKEN
    global HTTP_TIMEOUT

    action = queue_message['action']
    LOG_PREFIX = '[' + action + ']'
    SERVER_URL = args['serverUrl']
    API_TOKEN = args['apiToken']
    HTTP_TIMEOUT = args['httpTimeout']
    if not HTTP_TIMEOUT:
        HTTP_TIMEOUT = 30000
    else:
        HTTP_TIMEOUT = int(HTTP_TIMEOUT)

    if action == 'Close':
        send_close_request()
    elif action == "Acknowledge":
        send_acknowledge_request()
    elif action == "AddNote":
        send_add_note_request()


if __name__ == '__main__':
    main()
