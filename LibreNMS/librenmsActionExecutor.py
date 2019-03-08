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
parser.add_argument('-url', '--url', help='LibreNms Server Url', required=False)
parser.add_argument('-apiToken', '--apiToken', help='Api Token', required=False)
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


url = parse_field('url', True)
if url.endswith("/") and len(url) >= 2:
    url = url[0:len(url) - 2]

api_token = parse_field('apiToken', True)
rule = queue_message["rule"]
device_id = queue_message["device_id"]
timestamp = queue_message["timestamp"]
timeout = args['timeout']
if timeout is None:
    timeout = 30000
else:
    timeout = int(timeout)

logging.debug("Url: " + url)
logging.debug("ApiToken " + api_token)
logging.debug("Rule from OpsGenie Alert Details: " + rule)
logging.debug("Device ID from OpsGenie Alert Details: " + str(device_id))
logging.debug("Timestamp from OpsGenie Alert Details: " + str(timestamp))

list_rules_endpoint = url + "/api/v0/rules"

logging.debug("Sending GET request to " + list_rules_endpoint)

list_rules_response = requests.get(list_rules_endpoint, None, headers={"X-Auth-Token": api_token}, timeout=timeout)

logging.debug("Response from " + list_rules_endpoint + ": " + list_rules_response.text + "Status Code: "
              + str(list_rules_response.status_code))

if list_rules_response.status_code < 400:
    list_rules_response_map = list_rules_response.json()
    rules = list_rules_response_map["rules"]

    rule_id = next(v["id"] for (k, v) in rules.items() if v["rule"].strip().replace("\\\"", "\"") == rule.strip())

    logging.debug("Rule Id from LibreNMS: " + rule_id)

    if rule_id is not None:
        list_alerts_endpoint = url + "/api/v0/alerts"

        list_alerts_response = None

        if mapped_action == "ackAlert":

            query_params = {"state": "1"}
            logging.debug("Sending GET request to " + list_alerts_endpoint + "with parameters: "
                          + json.dumps(query_params))
            list_alerts_response = requests.get(list_alerts_endpoint, query_params, headers={"X-Auth-Token": api_token},
                                                timeout=timeout)

        elif mapped_action == "unmuteAlert":

            query_params = {"state": "2"}
            logging.debug("Sending GET request to " + list_alerts_endpoint + "with parameters: "
                          + json.dumps(query_params))
            list_alerts_response = requests.get(list_alerts_endpoint, query_params, headers={"X-Auth-Token": api_token},
                                                timeout=timeout)

        logging.debug(
            "Response from " + list_alerts_endpoint + ": " + list_alerts_response.json() + "Status Code: "
            + str(list_alerts_response.status_code))

        if list_alerts_response.status_code < 400:

            list_alerts_response_map = list_alerts_response.json()
            alerts = list_alerts_response_map['alerts']
            alert_id = str()

            if alerts:

                alerts = {key: value for (key, value) in alerts.items() if value["rule_id"] == rule_id and
                          value["device_id"] == device_id}

                if alerts:
                    if len(alerts) > 1:

                        timestamp_filtered_alerts = {key: value for (key, value) in alerts.items() if
                                                     value["timestamp"] == timestamp}

                        if timestamp_filtered_alerts and len(timestamp_filtered_alerts) > 0:
                            alert_id = timestamp_filtered_alerts[0]['id']
                            logging.debug(
                                "Found alert that matches the timestamp from Opsgenie alert, using that alert's alert id.")
                        else:
                            alert_id = alerts[0]['id']
                            logging.debug("Timestamp did not match the timestamp retrieved from Opsgenie alert,"
                                          + " using that alert ID of the first alert matches the rule and the device id.")

                    else:
                        alert_id = alerts[0]['id']
                        logging.debug(
                            "Found only one alert from the LibreNMS API response, using the alert ID of that alert.")

                else:
                    logging.error(
                        LOG_PREFIX + " Could not find any LibreNMS alerts that matches the alert from OpsGenie.")

            else:
                logging.error(
                    LOG_PREFIX + " Could not obtain alerts list from the list alerts response from LibreNMS API or found no matchin alerts.")

            logging.debug("Alert Id from LibreNMS: " + alert_id)

            if alert_id is not None:

                if mapped_action == "ackAlert":
                    url = url + "/api/v0/alerts/" + alert_id
                elif mapped_action == "unmuteAlert":
                    url = url + "/api/v0/alerts/unmute/" + alert_id

                logging.debug("Sending PUT request to " + url)

                response = requests.put(url, None, headers={"X-Auth-Token": api_token}, timeout=timeout)

                logging.debug("Response from " + url + ": " + response.json() + "Status Code: "
                              + str(response.status_code))

                if response.status_code < 400:
                    logging.info(LOG_PREFIX + ' Succesfully executed at LibreNMS.')
                    logging.debug(LOG_PREFIX + " LibreNMS response:" + response.json())
                else:
                    logging.error(
                        LOG_PREFIX + " Could not execute at LibreNMS; response: " + str(
                            response.status_code) + ' ' + response.text)
            else:
                logging.error(LOG_PREFIX + " Alert Id from the LibreNMS API was null.")
        else:
            logging.error(
                LOG_PREFIX + " Could not get alert list from LibreNMS; response: " + str(
                    list_alerts_response.status_code) + ' ' + list_alerts_response.text)
    else:
        logging.error(LOG_PREFIX + " Rule Id from the LibreNMS API was null.")
else:
    logging.error(
        LOG_PREFIX + " Could not get rules list from LibreNMS; response: " + str(
            list_rules_response.status_code) + ' ' + list_rules_response.text)
