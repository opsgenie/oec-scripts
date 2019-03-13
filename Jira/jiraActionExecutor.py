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
parser.add_argument('-loglevel', '--loglevel', help='Level of log', required=True)
parser.add_argument('-username', '--username', help='Username', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
parser.add_argument('-url', '--url', help='URL', required=False)
parser.add_argument('-projectKey', '--projectKey', help='Project Key', required=False)
parser.add_argument('-issueType', '--issueType', help='Issue Type', required=False)
args = vars(parser.parse_args())

logging.basicConfig(stream=sys.stdout, level=args['loglevel'])


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
    try:
        body = response.json()
        if body and response.status_code < 299:
            transition_list = body["transitions"]
            for transition in transition_list:
                to = transition['to']
                if transition_name == to['name']:
                    transition_id = transition['id']
            logging.info(LOG_PREFIX + " Successfully executed at Jira")
            logging.debug(LOG_PREFIX + " Jira response: " + str(response.status_code) + " " + str(response.content))
        else:
            logging.error(
                LOG_PREFIX + " Could not execute at Jira; response: " + str(response.content) + " status code: " + str(
                    response.status_code))
        if not transition_id:
            logging.debug(LOG_PREFIX + " Transition id is empty")
        return transition_id
    except ValueError:
        logging.error("The response body is not a valid json object!")


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
    url = parse_field('url', True)
    username = parse_field('username', True)
    password = parse_field('password', True)
    project_key = parse_field('projectKey', False)
    issue_type_name = parse_field('issueTypeName', False)

    issue_key = queue_message.get("key")

    logging.debug("Url: " + str(url))
    logging.debug("Username: " + str(username))
    logging.debug("Project Key: " + str(project_key))
    logging.debug("Issue Type: " + str(issue_type_name))
    logging.debug("Issue Key: " + str(issue_key))

    content_params = dict()

    token = HTTPBasicAuth(username, password)
    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "application/json",
    }

    result_url = url + "/rest/api/2/issue"

    if mapped_action == "addCommentToIssue":
        content_params = {
            "body": queue_message.get('body')
        }
        result_url += "/" + issue_key + "/comment"
    elif mapped_action == "createIssue":
        toLabel = "ogAlias:" + queue_message.get("alias")
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
        result_url += "/" + issue_key + "/transitions"
        content_params = {
            "transition": {
                "id": get_transition_id(headers, result_url, "Resolved")
            },
            "fields": {
                "resolution": {
                    "name": "Done"
                }
            }
        }
    elif mapped_action == "closeIssue":
        result_url += "/" + issue_key + "/transitions"
        content_params = {
            "transition": {
                "id": get_transition_id(headers, result_url, "Closed", token)
            },
            "fields": {
                "resolution": {
                    "name": "Done"
                }
            }
        }
    elif mapped_action == "issueDone":
        result_url += "/" + issue_key + "/transitions"
        content_params = {
            "transition": {
                "id": get_transition_id(headers, result_url, "Done", token)
            }
        }
    elif mapped_action == "inProgressIssue":
        result_url += "/" + issue_key + "/transitions"
        content_params = {
            "transition": {
                "id": get_transition_id(headers, result_url, "In Progress", token)
            }
        }

    logging.debug(str(content_params))
    response = requests.post(result_url, data=json.dumps(content_params), headers=headers, auth=token,
                             timeout=timeout)
    if response.status_code < 299:
        logging.info("Successfully executed at Jira")
        if mapped_action == "createIssue":
            try:
                response_body = response.json()
                if response_body:
                    issue_key_from_response = response_body['key']
                    if issue_key_from_response:
                        alert_api_url = args['opsgenieUrl'] + "/v2/alerts/" + alert_id + "/details"
                        content = {
                            "details":
                                {
                                    "issueKey": issue_key_from_response
                                }
                        }
                        headers = {
                            "Content-Type": "application/json",
                            "Accept-Language": "application/json",
                            "Authorization": "GenieKey " + args['apiKey']
                        }
                        logging.debug(str(alert_api_url) + str(content) + str(headers))
                        alert_response = requests.post(alert_api_url,
                                                       data=json.dumps(content), headers=headers,
                                                       timeout=timeout)
                        if alert_response.status_code < 299:
                            logging.info(LOG_PREFIX + " Successfully sent to Opsgenie")
                            logging.debug(
                                LOG_PREFIX + " Jira response: " + str(alert_response.content) + " " + str(
                                    alert_response.status_code))
                        else:
                            logging.warning(
                                LOG_PREFIX + " Could not execute at Opsgenie; response: " + str(
                                    alert_response.content) + " status code: " + str(alert_response.status_code))
                else:
                    logging.warning(
                        LOG_PREFIX + " Jira response is empty")
            except ValueError:
                logging.error()
    else:
        logging.warning(
            LOG_PREFIX + " Could not execute at Jira; response: " + str(response.content) + " status code: " + str(
                response.status_code))


if __name__ == '__main__':
    main()
