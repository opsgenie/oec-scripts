import argparse
import json
import logging
import sys

import requests
from requests.auth import HTTPBasicAuth

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Level of log', required=True)
parser.add_argument('-url', '--url', help='URL', required=False)
parser.add_argument('-username', '--username', help='Username', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
parser.add_argument('-key', '--key', help='Project key', required=False)
parser.add_argument('-issueTypeName', '--issueTypeName', help='Issue Type', required=False)
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


def get_transition_id(request_headers, jira_url, transition_name, token):
    transition_id = str()
    response = requests.get(jira_url, None, headers=request_headers, auth=token, timeout=timeout)
    body = response.json()
    if body != {} and response.status_code < 299:
        transition_list = body["transitions"]
        for transition in transition_list:
            to = transition['to']
            if transition_name == to['name']:
                transition_id = transition['id']
        logging.info(LOG_PREFIX + " Successfully executed at Jira Service Desk")
        logging.debug(
            LOG_PREFIX + " Jira Service Desk response: " + str(response.status_code) + " " + str(response.content))
    else:
        logging.error(
            LOG_PREFIX + " Could not execute at Jira Service Desk; response: " + str(
                response.content) + " status code: " + str(response.status_code))
    if transition_id:
        return transition_id
    else:
        logging.debug(LOG_PREFIX + " Transition id is empty")


def main():
    global LOG_PREFIX
    global queue_message
    global timeout

    queue_message_string = args['queuePayload']
    queue_message = json.loads(queue_message_string)

    logging.debug(str(queue_message))

    alert_id = queue_message["alert"]["alertId"]
    mapped_action = queue_message["mappedActionV2"]["name"]

    LOG_PREFIX = "[" + mapped_action + "]"
    logging.info("Will execute " + mapped_action + " for alertId " + alert_id)

    timeout = parse_timeout()
    url = parse_field('url', True)
    username = parse_field('username', True)
    password = parse_field('password', True)
    project_key = parse_field('key', False)
    issue_type_name = parse_field('issueTypeName', False)

    issue_key = queue_message.get("IssueKey")

    logging.debug("Url: " + str(url))
    logging.debug("Username: " + str(username))
    logging.debug("Project Key: " + str(project_key))
    logging.debug("Issue Type: " + str(issue_type_name))
    logging.debug("Issue Key: " + str(issue_key))

    content_params = dict()

    token = HTTPBasicAuth(username, password)
    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "application/json"
    }

    result_url = url + "/rest/api/2/issue"

    if mapped_action == "addComment":
        content_params = {
            "body": queue_message.get('body')
        }
        result_url += "/" + str(issue_key) + "/comment"
    elif mapped_action == "createIssue":
        toLabel = queue_message.get("alias")
        content_params = {
            "fields": {
                "project": {
                    "key": project_key
                },
                "issuetype": {
                    "name": issue_type_name
                },
                "summary": queue_message.get("summary"),
                "description": queue_message.get("description"),
                "labels": [toLabel.replace("\\s", "")]
            }
        }
    elif mapped_action == "resolveIssue":
        result_url += "/" + str(issue_key) + "/transitions"
        content_params = {
            "transition": {
                "id": get_transition_id(headers, result_url, "Resolved", token)
            },
            "fields": {
                "resolution": {
                    "name": "Done"
                }
            }
        }

    logging.debug(str(content_params))    
    response = requests.post(result_url, data=json.dumps(content_params), headers=headers, auth=token, timeout=timeout)
    if response.status_code < 299:
        logging.info("Successfully executed at Jira Service Desk")
        if mapped_action == "createIssue":
            if response.json():
                issue_key_from_response = response.json()['key']
                if issue_key_from_response:
                    alert_api_url = args.get('opsgenieUrl') + "/v2/alerts/" + alert_id + "/details"
                    content = {
                        "details":
                            {
                                "IssueKey": issue_key_from_response
                            }
                    }
                    headers = {
                        "Content-Type": "application/json",
                        "Accept-Language": "application/json",
                        "Authorization": "GenieKey " + args.get('apiKey')
                    }
                    alert_response = requests.post(alert_api_url,
                                                   data=json.dumps(content), headers=headers, timeout=timeout)
                    if alert_response.status_code < 299:
                        logging.info(LOG_PREFIX + " Successfully sent to Opsgenie")
                        logging.debug(
                            LOG_PREFIX + " Jira Service Desk response: " + str(alert_response.content) + " " + str(
                                alert_response.status_code))
                    else:
                        logging.warning(
                            LOG_PREFIX + " Could not execute at Opsgenie; response: " + str(
                                alert_response.content) + " status code: " + str(alert_response.status_code))
            else:
                logging.warning(
                    LOG_PREFIX + " Jira Service Desk response is empty")
    else:
        logging.warning(
            LOG_PREFIX + " Could not execute at Jira Service Desk; response: " + str(
                response.content) + " status code: " + str(response.status_code))


if __name__ == '__main__':
    main()
