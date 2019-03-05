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
parser.add_argument('-loglevel', '--loglevel', help='Log level', required=True)
parser.add_argument('-zendeskEmail', '--zendeskEmail', help='Zendesk Email', required=False)
parser.add_argument('-apiToken', '--apiToken', help='Api Token', required=False)
parser.add_argument('-subdomain', '--subdomain', help='Subdomain', required=False)
args = vars(parser.parse_args())

logging.basicConfig(stream=sys.stdout, level=args['loglevel'])

queue_message_string = args['queuePayload']
queue_message = json.loads(queue_message_string)

alert_id = queue_message["alert"]["alertId"]
mapped_action = queue_message["mappedAction"]["name"]

LOG_PREFIX = "[" + mapped_action + "]"


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


def parse_timeout():
    parsed_timeout = args['http.timeout']
    if not parsed_timeout:
        return 30000
    return int(parsed_timeout)


def main():
    logging.info("Will execute " + mapped_action + " for alertId " + alert_id)

    zendesk_email = parse_field('zendeskEmail', True) + '/token'
    api_token = parse_field('apiToken', True)

    timeout = parse_timeout()

    zendesk_url = queue_message["zendeskUrl"]
    if not zendesk_url.strip():
        zendesk_url = "https://" + parse_field('subdomain', True) + ".zendesk.com"

    ticket_id = queue_message["ticketId"]
    result_uri = zendesk_url + "/api/v2/tickets"

    logging.debug("Zendesk Email: " + zendesk_email)
    logging.debug("Zendesk Url: " + zendesk_url)
    logging.debug("Ticket Id: " + ticket_id)

    content_params = dict()

    if mapped_action == "addInternalComment":
        result_uri += "/" + ticket_id + ".json"
        content_params = {
            "ticket": {
                "comment": {
                    "body": queue_message['body'],
                    "public": False
                }
            }
        }
    elif mapped_action == "addPublicComment":
        result_uri += "/" + ticket_id + ".json"
        content_params = {
            "ticket": {
                "comment": {
                    "body": queue_message['body'],
                    "public": True
                }
            }
        }
    elif mapped_action == "createTicket":
        result_uri += ".json"
        content_params = {
            "ticket": {
                "comment": {
                    "body": queue_message['body'],
                    "public": False
                },
                "external_id": queue_message['externalId'],
                "subject": queue_message['subject'],
                "tags": queue_message['tags']
            }
        }
    elif mapped_action == "setStatusToClosed":
        result_uri += "/" + ticket_id + ".json"
        content_params = {
            "ticket": {
                "comment": {
                    "body": queue_message['body'],
                    "public": False
                },
                "status": queue_message['closed']
            }
        }
    elif mapped_action == "setStatusToOpen":
        result_uri += "/" + ticket_id + ".json"
        content_params = {
            "ticket": {
                "comment": {
                    "body": queue_message['body'],
                    "public": False
                },
                "status": queue_message['open']
            }
        }
    elif mapped_action == "setStatusToSolved":
        result_uri += "/" + ticket_id + ".json"
        content_params = {
            "ticket": {
                "comment": {
                    "body": queue_message['body'],
                    "public": False
                },
                "status": queue_message['solved']
            }
        }
    elif mapped_action == "setStatusToPending":
        result_uri += "/" + ticket_id + ".json"
        content_params = {
            "ticket": {
                "comment": {
                    "body": queue_message['body'],
                    "public": False
                },
                "status": queue_message['pending']
            }
        }

    logging.debug("Request Url: " + result_uri)
    logging.debug("Request Body: " + str(content_params))

    token = HTTPBasicAuth(zendesk_email, api_token)
    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "application/json",
    }

    if mapped_action == "createTicket":
        response = requests.post(result_uri, data=json.dumps(content_params), headers=headers, auth=token,
                                 timeout=timeout)
        if response.status_code < 299:
            logging.info("Successfully executed at Zendesk")
            ticket_from_response = response.json()['ticket']
            if ticket_from_response:
                ticket_id_from_response = str(ticket_from_response['id'])
                if ticket_id_from_response.strip():
                    alert_api_url = args['opsgenieUrl'] + "/" + alert_id + "/details"
                    content = {
                        "details": {
                            "og-internal-ticket_id": ticket_id_from_response
                        }
                    }
                    alert_api_headers = {
                        "Content-Type": "application/json",
                        "Accept-Language": "application/json",
                        "Authorization": "GenieKey " + args['apiKey']
                    }
                    alert_response = requests.post(alert_api_url,
                                                   data=json.dumps(content),
                                                   headers=alert_api_headers,
                                                   timeout=timeout)
                    if alert_response.status_code < 299:
                        logging.info("Successfully sent to Opsgenie")
                        logging.debug("Zendesk response: " + alert_response.content + " " + alert_response.status_code)
                    else:
                        logging.warning(
                            "Could not execute at Opsgenie; response: " + alert_response.content + " status code: " + alert_response.status_code)
        else:
            logging.warning(
                "Could not execute at Zendesk; response: " + response.content + " status code: " + response.status_code)
    else:
        response = requests.put(result_uri, data=json.dumps(content_params), headers=headers, auth=token)
        if response.status_code < 299:
            logging.info("Successfully executed at Zendesk")
        else:
            logging.warning(
                "Could not execute at Zendesk; response: " + response.content + " status code: " + response.status_code)


if __name__ == '__main__':
    main()
