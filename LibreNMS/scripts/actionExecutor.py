import argparse
import json
import logging
import sys

import requests

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--payload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Level of log', required=True)
parser.add_argument('-url', '--url', help='LibreNms Server Url', required=False)
parser.add_argument('-apiToken', '--apiToken', help='Api Token', required=False)
parser.add_argument('-timeout', '--timeout', help='Timeout', required=False)

args = vars(parser.parse_args())

logging.basicConfig(stream=sys.stdout, level=args['logLevel'])

queue_message_string = args['payload']
queue_message = json.loads(queue_message_string)

alert_id = queue_message["alert"]["alertId"]
mapped_action = queue_message["mappedActionV2"]["name"]

LOG_PREFIX = "[" + mapped_action + "]:"
logging.info(LOG_PREFIX + " Will execute " + mapped_action + " for alertId " + alert_id)


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


url = parse_field('url', True)
if url.endswith("/") and len(url) >= 2:
    url = url[0:len(url) - 2]

api_token = parse_field('apiToken', True)
rule = int(queue_message["rule"])
device_id = int(queue_message["deviceId"])
timestamp = queue_message["timestamp"]
timeout = args.get('timeout')
if timeout is None:
    timeout = 30000
else:
    timeout = int(timeout)

logging.debug("Url: " + str(url))
logging.debug("ApiToken " + str(api_token))
logging.debug("Rule from OpsGenie Alert Details: " + str(rule))
logging.debug("Device ID from OpsGenie Alert Details: " + str(device_id))
logging.debug("Timestamp from OpsGenie Alert Details: " + str(timestamp))

list_rules_endpoint = url + "/api/v0/rules"

logging.debug("Sending GET request to " + str(list_rules_endpoint))

list_rules_response = requests.get(list_rules_endpoint, None, headers={"X-Auth-Token": api_token}, timeout=timeout)

logging.debug("Response from " + str(list_rules_endpoint) + ": " + str(list_rules_response.text) + "Status Code: "
              + str(list_rules_response.status_code))

if list_rules_response.status_code < 400:
    rules = list_rules_response.json()["rules"]
    rule_id = None

    rule_list = [x["id"] for x in rules if x["id"] == rule]
    for x in rule_list:
        logging.debug(x)

    if len(rule_list) > 0:
        rule_id = rule_list[0]
        logging.debug("Rule Id from LibreNMS: " + str(rule_id))

        list_alerts_endpoint = url + "/api/v0/alerts"
        list_alerts_response = None

        if mapped_action == "ackAlert":
            query_params = {"state": "1"}
            logging.debug("Sending GET request to " + str(list_alerts_endpoint) + "with parameters: "
                          + json.dumps(query_params))
            list_alerts_response = requests.get(list_alerts_endpoint, query_params, headers={"X-Auth-Token": api_token},
                                                timeout=timeout)

        elif mapped_action == "unmuteAlert":
            query_params = {"state": "2"}
            logging.debug("Sending GET request to " + str(list_alerts_endpoint) + "with parameters: "
                          + json.dumps(query_params))
            list_alerts_response = requests.get(list_alerts_endpoint, query_params, headers={"X-Auth-Token": api_token},
                                                timeout=timeout)

        logging.debug(
            "Response from " + str(list_alerts_endpoint) + ": " + str(list_alerts_response.content) + "Status Code: "
            + str(list_alerts_response.status_code))

        if list_alerts_response.status_code < 400:
            alerts = list_alerts_response.json()['alerts']
            alert_id = None

            if len(alerts) > 0:
                alert_list = [x['id'] for x in alerts if (x['rule_id'] == rule and x['device_id'] == device_id and
                                                          x['timestamp'] == timestamp)]
                if len(alert_list) > 0:
                    alert_id = alert_list[0]
                    logging.debug("Alert ID: " + str(alert_id))
                    logging.debug(
                            "Found alert that matches the timestamp from Opsgenie alert, using that alert's alert id.")
                else:
                    alert_list = [x['id'] for x in alerts if (x['rule_id'] == rule and x['device_id'] == device_id)]
                    logging.debug("Timestamp did not match the timestamp retrieved from Opsgenie alert,"
                                  + " using that alert ID of the first alert matches the rule and the device id.")
                    alert_id = alert_list[0]
                    logging.debug("Alert ID: " + str(alert_id))
            else:
                logging.error(
                    LOG_PREFIX + " Could not obtain alerts list from the list alerts response from LibreNMS API or found no matching alerts.")

            logging.debug("Alert Id from LibreNMS: " + str(alert_id))
            if alert_id is not None:
                if mapped_action == "ackAlert":
                    url = url + "/api/v0/alerts/" + str(alert_id)
                elif mapped_action == "unmuteAlert":
                    url = url + "/api/v0/alerts/unmute/" + str(alert_id)

                logging.debug("Sending PUT request to " + str(url))

                response = requests.put(url, None, headers={"X-Auth-Token": api_token}, timeout=timeout)

                logging.debug("Response from " + url + ": " + str(response.content) + "Status Code: "
                              + str(response.status_code))

                if response.status_code < 400:
                    logging.info(LOG_PREFIX + ' Succesfully executed at LibreNMS.')
                    logging.debug(LOG_PREFIX + " LibreNMS response:" + str(response.content))
                else:
                    logging.error(
                        LOG_PREFIX + " Could not execute at LibreNMS; response: " + str(
                            response.status_code) + ' ' + str(response.text))
            else:
                logging.error(LOG_PREFIX + " Alert Id from the LibreNMS API was null.")
        else:
            logging.error(
                LOG_PREFIX + " Could not get alert list from LibreNMS; response: " + str(
                    list_alerts_response.status_code) + ' ' + str(list_alerts_response.text))
    else:
        logging.error(LOG_PREFIX + " Rule Id from the LibreNMS API was null.")
else:
    logging.error(
        LOG_PREFIX + " Could not get rules list from LibreNMS; response: " + str(
            list_rules_response.status_code) + ' ' + str(list_rules_response.text))

