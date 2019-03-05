import argparse
import json
import logging
import sys
import time
from xml.etree import ElementTree

import requests
from requests.auth import HTTPBasicAuth

parser = argparse.ArgumentParser()
parser.add_argument('-queuePayload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-loglevel', '--loglevel', help='Level of log', required=True)
parser.add_argument('-url', '--url', help='Url', required=False)
parser.add_argument('-username', '--username', help='Username', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
parser.add_argument('-workspaceName', '--workspaceName', help='Workspace Name', required=False)

args = vars(parser.parse_args())

queue_message_string = args['queuePayload']
queue_message = json.loads(queue_message_string)

logging.basicConfig(stream=sys.stdout, level=args['loglevel'])


def add_details(ticket_id, ticket_type, alert_id):
    endpoint = args['opsgenieUrl'] + '/v2/alerts/' + alert_id + '/details'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'GenieKey ' + args['apiKey']
    }
    body = {
        'details': {
            'ticketId': ticket_id,
            'ticketType': ticket_type
        }
    }
    r = requests.post(endpoint, data=body, headers=headers)
    logging.debug(LOG_PREFIX + 'Add details result ' + r.content + ' Status code: ' + r.status_code +
                  ("Reason: " + r.reason) if r.reason else "")


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


def get_workspace_id(workspace_name, url, auth):
    logging.debug(LOG_PREFIX + "Will send listContainerDefinitions request to"
                               " BMC FootPrints v12 Web Service API: " + url + ".")

    headers = {'content-type': 'text/xml; charset=UTF-8'}
    body = '''
        <?xml version='1.0' encoding='UTF-8'?>
        <soap-env:Envelope
            xmlns:soap-env='http://schemas.xmlsoap.org/soap/envelope/'
            xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
            xmlns:ext='http://externalapi.business.footprints.numarasoftware.com/'>
            <soap-env:Header />
            <soap-env:Body>
                <ext:listContainerDefinitions>
                    <listContainerDefinitionsRequest />
                </ext:listContainerDefinitions>
            </soap-env:Body>
        </soap-env:Envelope>
        '''
    response = requests.post(url, data=body, headers=headers, auth=auth)
    logging.debug("Response from BMC FootPrints v12 Web Service API: " + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")

    root = ElementTree.fromstring(response.content)
    definitions = root.findall('listContainerDefinitionsResponse')[0].findall('return')[0].findall('_definitions')
    for d in definitions:
        if d.find('_definitionName').text == workspace_name:
            return d.find('_definitionId').text
    return ""


def get_item_definition_id(workspace_id, item_type, url, auth):
    logging.debug(LOG_PREFIX + "Will send listItemDefinitions request to"
                               " BMC FootPrints v12 Web Service API:: " + url + ".")
    headers = {'content-type': 'text/xml; charset=UTF-8'}
    body = '''
        <?xml version='1.0' encoding='UTF-8'?>
        <soap-env:Envelope
            xmlns:soap-env='http://schemas.xmlsoap.org/soap/envelope/'
            xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
            xmlns:ext='http://externalapi.business.footprints.numarasoftware.com/'>
            <soap-env:Header />
            <soap-env:Body>
                <ext:listItemDefinitions>
                    <listItemDefinitionsRequest>
                        <_containerDefinitionId>{0}</_containerDefinitionId>
                    </listItemDefinitionsRequest>
                </ext:listItemDefinitions>
            </soap-env:Body>
        </soap-env:Envelope>
    '''.format(workspace_id)
    response = requests.post(url, data=body, headers=headers, auth=auth)
    logging.debug("Response from BMC FootPrints v12 Web Service API: " + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")

    root = ElementTree.fromstring(response.content)
    definitions = root.findall('listItemDefinitionsResponse')[0].findall('return')[0].findall('_definitions')
    for d in definitions:
        if d.find('_definitionName').text == item_type:
            return d.find('_definitionId').text
    return ""


def create_ticket(item_definition_id, short_description, description, priority, alert_alias, ticket_type, url, auth):
    logging.debug(LOG_PREFIX + "Will send createTicket request to BMC FootPrints v12 Web Service API: " + url + ".")

    status_field = "Request" if ticket_type == "Incident" else "Pending review"
    headers = {'content-type': 'text/xml; charset=UTF-8'}
    body = '''
    <?xml version='1.0' encoding='UTF-8'?>
    <soap-env:Envelope
        xmlns:soap-env='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:ext='http://externalapi.business.footprints.numarasoftware.com/'>
        <soap-env:Header />
        <soap-env:Body>
            <ext:createTicket>
                <createTicketRequest>
                    <_ticketDefinitionId>{0}</_ticketDefinitionId>
                    <_ticketFields>
                        <itemFields>
                            <fieldName>OpsGenie Alert Alias</fieldName>
                            <fieldValue>
                                <value>{1}</value>
                            </fieldValue>
                        </itemFields>
                        <itemFields>
                            <fieldName>Description</fieldName>
                            <fieldValue>
                                <value>{2}</value>
                            </fieldValue>
                        </itemFields>
                        <itemFields>
                            <fieldName>Short Description</fieldName>
                            <fieldValue>
                                <value>{3}</value>
                            </fieldValue>
                        </itemFields>
                        <itemFields>
                            <fieldName>Status</fieldName>
                            <fieldValue>
                                <value>{4}</value>
                            </fieldValue>
                        </itemFields>
                        <itemFields>
                            <fieldName>Priority</fieldName>
                            <fieldValue>
                                <value>{5}</value>
                            </fieldValue>
                        </itemFields>
                    </_ticketFields>
                </createTicketRequest>
            </ext:createTicket>
        </soap-env:Body>
    </soap-env:Envelope>
    '''.format(item_definition_id, alert_alias, description, short_description, status_field, priority)
    response = requests.post(url, data=body, headers=headers, auth=auth)
    logging.debug("Response from BMC FootPrints v12 Web Service API: " + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")

    root = ElementTree.fromstring(response.content)
    return root.findall('createTicketResponse')[0].findall('return')[0]


def update_ticket_description(ticket_definition_id, ticket_id, new_description, url, auth):
    logging.debug(LOG_PREFIX + "Will send editTicket request for updating ticket description to BMC FootPrints v12 "
                               "Web Service API: " + url + ".")

    headers = {'content-type': 'text/xml; charset=UTF-8'}
    body = '''
    <?xml version='1.0' encoding='UTF-8'?>
    <soap-env:Envelope
        xmlns:soap-env='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:ext='http://externalapi.business.footprints.numarasoftware.com/'>
        <soap-env:Header />
        <soap-env:Body>
            <ext:editTicket>
                <editTicketRequest>
                    <_ticketDefinitionId>{0}</_ticketDefinitionId>
                    <_ticketId>{1}</_ticketId>
                    <_ticketFields>
                        <itemFields>
                            <fieldName>Description</fieldName>
                            <fieldValue>
                                <value>{2}</value>
                            </fieldValue>
                        </itemFields>
                    </_ticketFields>
                </editTicketRequest>
            </ext:editTicket>
        </soap-env:Body>
    </soap-env:Envelope>
    '''.format(ticket_definition_id, ticket_id, new_description)
    response = requests.post(url, data=body, headers=headers, auth=auth)
    logging.debug("Response from BMC FootPrints v12 Web Service API: " + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")


def update_ticket_priority(ticket_definition_id, ticket_id, new_description, priority, url, auth):
    logging.debug(LOG_PREFIX + "Will send editTicket request for updating ticket description to BMC FootPrints v12 "
                               "Web Service API: " + url + ".")
    headers = {'content-type': 'text/xml; charset=UTF-8'}
    body = '''
    <?xml version='1.0' encoding='UTF-8'?>
    <soap-env:Envelope
        xmlns:soap-env='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:ext='http://externalapi.business.footprints.numarasoftware.com/'>
        <soap-env:Header />
        <soap-env:Body>
            <ext:editTicket>
                <editTicketRequest>
                    <_ticketDefinitionId>{0}</_ticketDefinitionId>
                    <_ticketId>{1}</_ticketId>
                    <_ticketFields>
                        <itemFields>
                            <fieldName>Description</fieldName>
                            <fieldValue>
                                <value>{2}</value>
                            </fieldValue>
                        </itemFields>
                        <itemFields>
                            <fieldName>Priority</fieldName>
                            <fieldValue>
                                <value>{3}</value>
                            </fieldValue>
                        </itemFields>
                    </_ticketFields>
                </editTicketRequest>
            </ext:editTicket>
        </soap-env:Body>
    </soap-env:Envelope>
    '''.format(ticket_definition_id, ticket_id, new_description, priority)
    response = requests.post(url, data=body, headers=headers, auth=auth)
    logging.debug("Response from BMC FootPrints v12 Web Service API: " + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")


def resolve_ticket(ticket_definition_id, ticket_id, resolution, url, auth):
    logging.debug(LOG_PREFIX + "Will send editTicket request for resolving to BMC FootPrints v12 "
                               "Web Service API: " + url + ".")
    resolution_date = time.strftime('%Y-%m-%dT%H:%M:%S')
    headers = {'content-type': 'text/xml; charset=UTF-8'}
    body = '''
    <?xml version='1.0' encoding='UTF-8'?>
    <soap-env:Envelope
        xmlns:soap-env='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:ext='http://externalapi.business.footprints.numarasoftware.com/'>
        <soap-env:Header />
        <soap-env:Body>
            <ext:editTicket>
                <editTicketRequest>
                    <_ticketDefinitionId>{0}</_ticketDefinitionId>
                    <_ticketId>{1}</_ticketId>
                    <_ticketFields>
                        <itemFields>
                            <fieldName>Description</fieldName>
                            <fieldValue>
                                <value>{2}</value>
                            </fieldValue>
                        </itemFields>
                        <itemFields>
                            <fieldName>Resolution</fieldName>
                            <fieldValue>
                                <value>{2}</value>
                            </fieldValue>
                        </itemFields>
                        <itemFields>
                            <fieldName>Resolution Date &amp; Time</fieldName>
                            <fieldValue>
                                <value>{3}</value>
                            </fieldValue>
                        </itemFields>
                    </_ticketFields>
                </editTicketRequest>
            </ext:editTicket>
        </soap-env:Body>
    </soap-env:Envelope>
    '''.format(ticket_definition_id, ticket_id, resolution, resolution_date)
    response = requests.post(url, data=body, headers=headers, auth=auth)
    logging.debug("Response from BMC FootPrints v12 Web Service API: " + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")


def convert_priority(priority):
    if priority == 'P1':
        return "1-Critical"
    elif priority == 'P2':
        return "2-High"
    elif priority == 'P3':
        return "3-Medium"
    elif priority == 'P4':
        return "4-Low"
    elif priority == 'P5':
        return "5-Planning"
    return "3-Medium"


def main():
    global LOG_PREFIX
    global BMC_FOOTPRINTS_WEB_SERVICE_EXTENSION

    alert_id = queue_message['alert']['alertId']
    mapped_action = queue_message['mappedAction']['name']
    ticket_id = queue_message['ticketId']
    short_description = queue_message['short_description']
    description = queue_message['description']
    priority = queue_message['priority']
    ticket_type = queue_message['ticketType']
    alert_alias = queue_message['alertAlias']

    BMC_FOOTPRINTS_WEB_SERVICE_EXTENSION = '/footprints/servicedesk/externalapisoap/ExternalApiServicePort?wsdl'
    LOG_PREFIX = '[' + mapped_action + ']'
    logging.info(LOG_PREFIX + ' Will execute ' + mapped_action + ' for alertId ' + alert_id)

    url = parse_field('url', True)
    if url[-1] == '/':
        url = url[:-1] + BMC_FOOTPRINTS_WEB_SERVICE_EXTENSION
    else:
        url += BMC_FOOTPRINTS_WEB_SERVICE_EXTENSION
    username = parse_field('username', True)
    password = parse_field('password', True)
    workspace_name = parse_field('workspaceName', False)
    priority = convert_priority(priority)
    auth = HTTPBasicAuth(username, password)

    workspace_id = get_workspace_id(workspace_name, url, auth)
    if not workspace_id:
        logging.error(LOG_PREFIX + 'Cannot obtain workspace ID from BMC FootPrints v12.')
        return
    item_definition_id = get_item_definition_id(workspace_id, ticket_type, url, auth)
    if not item_definition_id:
        logging.error(LOG_PREFIX + 'Cannot obtain item definition ID for ' + ticket_type +
                      ' from BMC FootPrints v12.')
        return
    if mapped_action == 'createIncident' or mapped_action == 'createProblem':
        ticket_type = 'Incident' if mapped_action == 'createIncident' else 'Problem'
        item_id = create_ticket(item_definition_id, short_description, description, priority, alert_alias,
                                ticket_type, url, auth)
        if not item_id:
            logging.error(LOG_PREFIX + 'Cannot obtain item ID for item definition ID ' + item_definition_id +
                          ' from BMC FootPrints v12.')
            return
        add_details(item_id, ticket_type, alert_id)
    elif mapped_action == 'updateDescription':
        update_ticket_description(item_definition_id, ticket_id, description, url, auth)
    elif mapped_action == 'updatePriority':
        update_ticket_priority(item_definition_id, ticket_id, description, priority, url, auth)
    elif mapped_action == 'resolveTicket':
        resolve_ticket(item_definition_id, ticket_id, description, url, auth)
    else:
        logging.warning(LOG_PREFIX + "Skipping" + mapped_action + "action, could not determine the mapped action.")


if __name__ == '__main__':
    main()
