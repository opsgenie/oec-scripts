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


def send_request_to_trackit(final_url, content, headers):
    response = requests.post(final_url, json.dumps(content), headers=headers, timeout=timeout)
    if response.status_code < 299:
        logging.info(LOG_PREFIX + " Successfully executed at TrackIt.")
    else:
        logging.warning(
            LOG_PREFIX + " Could not execute at TrackIt; response: " + str(response.content) + " " + str(
                response.status_code))


def login_to_trackit():
    final_url = url + "/TrackitWeb/api/login?username=" + parse_field("login",
                                                                      True) + "&pwd=" + parse_field(
        "password", True)
    logging.debug("Url: " + str(final_url))
    response = requests.get(final_url)
    if response:
        response_map = response.json()
        if response_map:
            return response_map['data']['apiKey']

    return None


def add_note_to_workflow(message, workflow_id, track_key):
    final_url = url + "/TrackitWeb/api/workorder/AddNote/" + workflow_id
    headers = {
        "Content-Type": "text/json",
        "Accept": "text/json",
        "TrackitAPIKey": track_key
    }
    content = {
        "IsPrivate": "False",
        "FullText": message
    }
    logging.debug(
        "Before Post -> Url: " + final_url + ", Content: " + str(content) + ", Request Headers: " + str(headers))
    send_request_to_trackit(final_url, content, headers)


def close_workflow(workflow_id, track_key):
    final_url = url + "/TrackitWeb/api/workorder/Close/" + workflow_id
    headers = {
        "Content-Type": "text/json",
        "Accept": "text/json",
        "TrackitAPIKey": track_key
    }
    logging.debug("Before Post -> Url: " + final_url + ", " + "Request Headers: " + str(headers))
    send_request_to_trackit(final_url, {}, headers)


def main():
    global queue_message
    global LOG_PREFIX
    global timeout
    global url

    queue_message_string = args['queuePayload']
    queue_message = json.loads(queue_message_string)
    alert = queue_message["alert"]
    alert_id = alert["alertId"]
    action = queue_message["action"]

    timeout = parse_timeout()

    LOG_PREFIX = "[" + action + "]"
    logging.info("Will execute " + action + " for alertId " + alert_id)
    url = parse_field("url", True)
    track_key = login_to_trackit()
    workflow_id = str(alert["details"]["workflow_id"])
    user_name = str(alert['username'])
    message = str(alert['message'])

    if workflow_id:
        message = user_name + " executed [" + action + "] action on alert: \"" + message + "\""

        if action == "Acknowledge":
            message = user_name + " acknowledged alert: \"" + message + "\""
        elif action == "AddNote":
            note = str(alert['note'])
            message = user_name + " noted: \"" + note + "\" on alert: \"" + message + "\""
        elif action == "AddRecipient":
            recipient = str(alert['recipient'])
            message = user_name + " added recipient " + recipient + " to alert: \"" + message + "\""
        elif action == "AddTeam":
            team = str(alert['team'])
            message = user_name + " added team " + team + " to alert: \"" + message + "\""
        elif action == "AssignOwnership":
            owner = str(alert['owner'])
            message = user_name + " assigned ownership of the alert: \"" + message + "\" to " + \
                      owner
        elif action == "TakeOwnership":
            owner = str(alert['owner'])
            message = user_name + " took ownership of the alert: \"" + message + "\""

        if action != "Close":
            add_note_to_workflow(message, workflow_id, track_key)
        else:
            close_workflow(workflow_id, track_key)
    else:
        logging.warning(LOG_PREFIX + " Cannot send action to Track-It because workflow_id is not found on alert")
if __name__ == '__main__':
    main()
