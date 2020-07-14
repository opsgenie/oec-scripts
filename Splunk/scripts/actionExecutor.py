import argparse
import json
import logging
import sys

import requests

parser = argparse.ArgumentParser()
parser.add_argument("-payload", "--queuePayload",
                    help="Payload from queue", required=True)
parser.add_argument("-apiKey", "--apiKey",
                    help="The apiKey of the integration", required=True)
parser.add_argument("-opsgenieUrl", "--opsgenieUrl",
                    help="Opsgenie apiUrl", required=True)
parser.add_argument("-logLevel", "--logLevel",
                    help="Level of logging", required=True)
parser.add_argument("-url", "--url",
                    help="Splunk base url with port", required=False)
parser.add_argument("-token", "--token",
                    help="Splunk http event collector token", required=False)
parser.add_argument("-sslVerify", "--sslverify",
                    help="SSL verify your splunk server url", required=False)

args = vars(parser.parse_args())

logging.basicConfig(stream=sys.stdout, level=args["logLevel"])

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

def main():
    global queue_message

    queue_message_string = args["queuePayload"]
    queue_message_string = queue_message_string.strip()
    queue_message = json.loads(queue_message_string)

    action = queue_message["action"]
    alert_id = queue_message["alertId"]

    log_prefix = "[{}]".format(action)
    logging.info("Will execute {} for alertId {}".format(action, alert_id))

    splunk_url = parse_field('url', True)
    splunk_token = parse_field('token', True)
    ssl_verify = parse_field('sslverify', False)

    if not ssl_verify or ssl_verify.lower() == "false":
        ssl_verify = False
    else:
        ssl_verify = True

    del queue_message["url"]
    del queue_message["token"]

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Splunk {}".format(splunk_token)
    }

    target_url = "{}/services/collector".format(splunk_url)
    body = {
        "event": queue_message
    }

    response = requests.post(target_url, data=json.dumps(body), headers=headers, verify=ssl_verify)
    if response.status_code < 299:
        logging.info(log_prefix + " Successfully relayed payload to Splunk")
    else:
        logging.warning(log_prefix + " Could not relay to Splunk; response: {} status code: {}".format(
            str(response.content), response.status_code))


if __name__ == "__main__":
    main()
