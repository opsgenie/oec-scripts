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
parser.add_argument('-username', '--username', help='Username', required=False)
parser.add_argument('-passhash', '--passhash', help='Passhash', required=False)
parser.add_argument('-prtgUrl', '--prtgUrl', help='PRTG Url', required=False)
parser.add_argument('-sensorId', '--sensorId', help='Sensor Id', required=False)
parser.add_argument('-acknowledgeMessage', '--acknowledgeMessage', help='Acknowledge Message', required=False)
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
    global timeout

    queue_message_string = args['queuePayload']
    queue_message_string = queue_message_string.strip()
    queue_message = json.loads(queue_message_string)

    alert_id = queue_message["alertId"]
    mapped_action = queue_message["mappedActionV2"]["name"]

    LOG_PREFIX = "[" + mapped_action + "]"

    logging.info("Will execute " + mapped_action + " for alertId " + alert_id)

    timeout = parse_timeout()
    url = parse_field('prtgUrl', True)
    username = parse_field('username', True)
    passhash = parse_field('passhash', True)
    ackMessage = parse_field('acknowledgeMessage', True)
    id = parse_field('sensorId', True)

    prtgPath = "/api/acknowledgealarm.htm"
    if url.endswith("/"):
        prtgPath = "api/acknowledgealarm.htm"

    result_url = url + prtgPath

    params = {
        'id': id,
        'ackmsg': ackMessage,
        'username': username,
        'passhash': passhash
    }
    logging.debug("Sending request to PRTG.")
    response = requests.post(result_url, params=params, timeout=timeout)
    if response.status_code < 300:
        logging.info("Successfully executed at PRTG")

    else:
        logging.warning(
            LOG_PREFIX + " Could not execute at PRTG; response: " + str(response.content) + " status code: " + str(
                response.status_code))


if __name__ == '__main__':
    main()
