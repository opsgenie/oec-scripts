import argparse
import json
import logging
import sys
from xml.sax.saxutils import escape

import requests
from requests.auth import HTTPBasicAuth

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--payload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-filepath', '--filepath', help='Filepath', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Level of log', required=True)
parser.add_argument('-userName', '--userName', help='Username', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
parser.add_argument('-url', '--url', help='Url', required=False)
parser.add_argument('-profileName', '--profileName', help='Profile Name', required=False)
parser.add_argument('-timeout', '--timeout', help='Timeout', required=False)

args = vars(parser.parse_args())

logging.basicConfig(stream=sys.stdout, level=args['logLevel'])

queue_message_string = args['payload']
queue_message = json.loads(queue_message_string)


def create_xml(mapped_action, incident_id):
    state = ''

    if mapped_action == "confirmIncident":
        state = "Confirmed"
    elif mapped_action == "inProgressIncident":
        state = "InProgress"

    data = {'id': escape(incident_id), 'state': escape(state)}

    xml_format = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
                <incident id="%(id)s">        
                <state>%(state)s</state>
                </incident>"""

    return xml_format % data


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


def main():
    global LOG_PREFIX

    alert_id = queue_message["alert"]["alertId"]
    mapped_action = queue_message["mappedActionV2"]["name"]

    LOG_PREFIX = "[" + mapped_action + "]:"
    logging.info(LOG_PREFIX + " Will execute " + mapped_action + " for alertId " + alert_id)

    username = parse_field('userName', True)
    password = parse_field('password', True)

    url = parse_field('url', True)
    profile_name = parse_field('profileName', True)

    incident_rule = queue_message["incidentRule"]
    incident_id = queue_message["alias"]
    timeout = args['timeout']
    if not timeout:
        timeout = 30000
    else:
        timeout = int(timeout)

    logging.debug("Url: " + url)
    logging.debug("Username: " + username)
    logging.debug("Profile Name: " + profile_name)
    logging.debug("Incident Rule: " + str(incident_rule))
    logging.debug("Incident Id: " + str(incident_id))

    content_params = create_xml(mapped_action, incident_id)

    result_url = url + "/rest/management/profiles/" + profile_name + "/incidentRules/" + incident_rule + "/incidents/" \
                 + incident_id

    logging.debug("URL: " + result_url)

    auth_token = HTTPBasicAuth(username, password)

    response = requests.put(result_url, content_params, headers={"Content-Type": "application/xml"}, auth=auth_token,
                            timeout=timeout)

    if response:
        if response.status_code < 400:
            logging.info(LOG_PREFIX + " Successfully executed at DynatraceAppMon. ")
            logging.debug(
                LOG_PREFIX + " DynatraceAppMon response: " + str(response.content) + " response code: " + str(
                    response.status_code))
        else:
            logging.error(LOG_PREFIX + " Could not execute at DynatraceAppMon; status code: " + str(
                response.status_code) + "response: " + str(response.content))


if __name__ == '__main__':
    main()
