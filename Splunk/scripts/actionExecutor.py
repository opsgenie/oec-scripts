import argparse
import json
import logging
import sys

import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-payload", "--queuePayload",
                        help="Payload from queue", required=True)
    parser.add_argument("-apiKey", "--apiKey",
                        help="The apiKey of the integration", required=True)
    parser.add_argument("-opsgenieUrl", "--opsgenieUrl",
                        help="Opsgenie apiUrl", required=True)
    parser.add_argument("-logLevel", "--logLevel",
                        help="Level of logging", required=True)

    args = vars(parser.parse_args())

    logging.basicConfig(stream=sys.stdout, level=args["logLevel"])

    queue_message_string = args["queuePayload"]
    queue_message_string = queue_message_string.strip()
    queue_message = json.loads(queue_message_string)

    action = queue_message["action"]
    alert_id = queue_message["alertId"]

    log_prefix = "[{}]".format(action)
    logging.info("Will execute {} for alertId {}".format(action, alert_id))

    splunkUrl = queue_message["url"]
    splunkToken = queue_message["token"]

    del queue_message["url"]
    del queue_message["token"]

    headers = {
        "Content-Type": "application/json",
        "Authorization": "Splunk {}".format(splunkToken)
    }

    targetUrl = "{}/services/collector".format(splunkUrl)
    body = {
        "event": queue_message,
        "sourcetype": "manual"
    }

    response = requests.post(targetUrl, data=json.dumps(body), headers=headers)
    if response.status_code < 299:
        logging.info(log_prefix + " Successfully relayed payload to Splunk")
    else:
        logging.warning(log_prefix + " Could not relay to Splunk; response: {} status code: {}".format(
            str(response.content), response.status_code))


if __name__ == "__main__":
    main()
