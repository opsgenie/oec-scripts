import argparse
import json
import sys

import requests
import logging

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--payload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-loglevel', '--loglevel', help='Level of log', required=True)
parser.add_argument('-url', '--url', help='Your Solarwinds MSP N-central server IP or FQDN', required=False)
parser.add_argument('-username', '--username', help='Name of Solarwinds MSP N-central user that can acknowledge alerts',
                    required=False)
parser.add_argument('-password', '--password',
                    help='Password for Solarwinds MSP N-central user that can acknowledge alerts',
                    required=False)
parser.add_argument('-timeout', '--timeout', help='Timeout', required=False)

args = vars(parser.parse_args())

logging.basicConfig(stream=sys.stdout, level=args['loglevel'])

queue_message_string = args['payload']
queue_message = json.loads(queue_message_string)

alert_id = queue_message["alert"]["alertId"]
mapped_action = queue_message["mappedAction"]["name"]

LOG_PREFIX = "[" + mapped_action + "]:"
logging.info(LOG_PREFIX + " Will execute " + mapped_action + " for alertId " + alert_id)


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


username = parse_field('username', True)
password = parse_field('password', True)
url = parse_field('url', True)
timeout = args['timeout']

if timeout is None:
    timeout = 30000
else:
    timeout = int(timeout)

active_notification_trigger_Id = queue_message["activeNotificationTriggerID"]

logging.debug("Username: " + username)
logging.debug("Password: " + password)
logging.debug("Url: " + url)
logging.debug("activeNotificationTriggerID: " + str(active_notification_trigger_Id))

if mapped_action == "acknowledgeNotification":
    soapEndpoint = url + "/dms2/services2/ServerEI2"
    logging.debug("SOAP Endpoint: " + soapEndpoint)

    headers = {'content-type': 'text/xml; charset=UTF-8'}

    body = '''
        <?xml version='1.0' encoding='UTF-8'?>
        <soap-env:Envelope
            xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'
            xmlns:ei2:'http://ei2.nobj.nable.com/'>
            <soap-env:Header />
            <soap-env:Body>
                <ei2:acknowledgeNotification>
                    <ei2:activeNotificationTriggerIDArray>{0}</ei2:activeNotificationTriggerIDArray>
                    <ei2:user>{1}</ei2:user>
                    <ei2:password>{2}</ei2:password>
                    <ei2:addToDeviceNotes>true</ei2:addToDeviceNotes> 
                    <ei2:suppressOnEscalation>false</ei2:suppressOnEscalation> 
                </ei2:acknowledgeNotification>
            </soap-env:Body>
        </soap-env:Envelope>
        '''.format(active_notification_trigger_Id, username, password)

    response = requests.post(url, data=body, headers=headers, timeout=timeout)

    logging.debug("Status code of the response: " + str(response.status_code))
    logging.debug("Response content: " + str(response.content))

    if 300 > response.status_code:
        logging.info("SOAP request sent successfully.")
    else:
        logging.error("SOAP request failed with status code: " + str(response.status_code))
