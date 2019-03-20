import argparse
import json
import logging
import sys
from xml.etree import ElementTree

import requests

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Level of log', required=True)
parser.add_argument('-url', '--url', help='Url', required=False)
parser.add_argument('-username', '--username', help='Username', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
parser.add_argument('-incidentWorkspaceId', '--incidentWorkspaceId', help='Incident Workspace ID', required=False)
parser.add_argument('-problemWorkspaceId', '--problemWorkspaceId', help='Problem Workspace ID', required=False)

args = vars(parser.parse_args())

queue_message_string = args['queuePayload']
queue_message = json.loads(queue_message_string)

logging.basicConfig(stream=sys.stdout, level=args['logLevel'])


def add_details(issue_number, alert_id):
    endpoint = args['opsgenieUrl'] + '/v2/alerts/' + alert_id + '/details'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'GenieKey ' + args['apiKey']
    }
    body = {
        'details': {
            'issueNumber': issue_number,
            'issueType': 'Problem'
        }
    }
    r = requests.post(endpoint, json=body, headers=headers)
    logging.debug(LOG_PREFIX + 'Add details result ' + str(r.content) + ' Status code: ' + str(r.status_code) +
                  ("Reason: " + str(r.reason)) if r.reason else "")


def create_issue(url, username, password, alert_alias, priority, description, title, identifier_id):
    logging.debug(LOG_PREFIX + "Will send createIssue request to BMC FootPrints v11 Web Service API: " + url + ".")
    headers = {'content-type': 'text/xml; charset=UTF-8'}
    body = '''
    <?xml version='1.0' encoding='UTF-8'?>
    <soap-env:Envelope
        xmlns:soap-env='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:SOAP-ENC='http://schemas.xmlsoap.org/soap/encoding/'
        xmlns:namesp2='http://xml.apache.org/xml-soap'
        xmlns:xsd='http://www.w3.org/1999/XMLSchema'
        xmlns:xsi='http://www.w3.org/1999/XMLSchema-instance'>
        <soap-env:Header />
        <soap-env:Body>
            <namesp1:MRWebServices__createIssue
                xmlns:namesp1='MRWebServices'>
                <user xsi:type='xsd:string'>{0}</user>
                <password xsi:type='xsd:string'>{1}</password>
                <extrainfo xsi:type='xsd:string' />
                <args xsi:type='namesp2:SOAPStruct'>
                    <projfields xsi:type='namesp2:SOAPStruct'>
                        <OpsGenie__bAlert__bAlias>{2}</OpsGenie__bAlert__bAlias>
                    </projfields>
                    <priorityNumber xsi:type='xsd:int'>{3}</priorityNumber>
                    <status xsi:type='xsd:string'>Open</status>
                    <description xsi:type='xsd:string'>{4}</description>
                    <title xsi:type='xsd:string'>{5}</title>
                    <projectID xsi:type='xsd:int'>{6}</projectID>
                </args>
            </namesp1:MRWebServices__createIssue>
        </soap-env:Body>
    </soap-env:Envelope>         
    '''.format(username, password, alert_alias, priority, description, title, identifier_id)

    response = requests.post(url, data=body, headers=headers)
    logging.debug("Response from BMC FootPrints v11 Web Service API: " + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")

    tree = ElementTree.fromstring(response.content)

    for item in tree.getiterator():
        if item.tag == 'return':
            return item.text
    return ""


def update_issue_description(url, username, password, description, identifier_id, issue_number):
    logging.debug(
        LOG_PREFIX + "Will send editIssue request for updating issue description to BMC FootPrints v11 Web Service "
                     "API: " + url + ".")
    headers = {'content-type': 'text/xml; charset=UTF-8'}
    body = '''
    <?xml version='1.0' encoding='UTF-8'?>
    <soap-env:Envelope
        xmlns:soap-env='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:SOAP-ENC='http://schemas.xmlsoap.org/soap/encoding/'
        xmlns:namesp2='http://xml.apache.org/xml-soap'
        xmlns:xsd='http://www.w3.org/1999/XMLSchema'
        xmlns:xsi='http://www.w3.org/1999/XMLSchema-instance'>
        <soap-env:Header />
        <soap-env:Body>
            <namesp1:MRWebServices__editIssue
                xmlns:namesp1='MRWebServices'>
                <user xsi:type='xsd:string'>{0}</user>
                <password xsi:type='xsd:string'>{1}</password>
                <extrainfo xsi:type='xsd:string' />
                <args xsi:type='namesp2:SOAPStruct'>
                    <description xsi:type='xsd:string'>{2}</description>
                    <projectID xsi:type='xsd:int'>{3}</projectID>
                    <mrID xsi:type='xsd:int'>{4}</mrID>
                </args>
            </namesp1:MRWebServices__editIssue>
        </soap-env:Body>
    </soap-env:Envelope>
    '''.format(username, password, description, identifier_id, issue_number)

    response = requests.post(url, data=body, headers=headers)

    logging.debug("Response from BMC FootPrints v11 Web Service API: " + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")


def update_issue_priority(url, username, password, priority, identifier_id, issue_number):
    logging.debug(LOG_PREFIX + "Will send editIssue request for updating issue priority to BMC FootPrints v11 Web "
                               "Service API: " + url)
    headers = {'content-type': 'text/xml; charset=UTF-8'}
    body = '''
    <?xml version='1.0' encoding='UTF-8'?>
    <soap-env:Envelope
        xmlns:soap-env='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:SOAP-ENC='http://schemas.xmlsoap.org/soap/encoding/'
        xmlns:namesp2='http://xml.apache.org/xml-soap'
        xmlns:xsd='http://www.w3.org/1999/XMLSchema'
        xmlns:xsi='http://www.w3.org/1999/XMLSchema-instance'>
        <soap-env:Header />
        <soap-env:Body>
            <namesp1:MRWebServices__editIssue
                xmlns:namesp1='MRWebServices'>
                <user xsi:type='xsd:string'>{0}</user>
                <password xsi:type='xsd:string'>{1}</password>
                <extrainfo xsi:type='xsd:string' />
                <args xsi:type='namesp2:SOAPStruct'>
                    <priorityNumber xsi:type='xsd:int'>{2}</priorityNumber>
                    <projectID xsi:type='xsd:int'>{3}</projectID>
                    <mrID xsi:type='xsd:int'>{4}</mrID>
                </args>
            </namesp1:MRWebServices__editIssue>
        </soap-env:Body>
    </soap-env:Envelope>
    '''.format(username, password, priority, identifier_id, issue_number)

    response = requests.post(url, data=body, headers=headers)

    logging.debug('Response from BMC FootPrints v11 Web Service API: ' + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")


def resolve_issue(url, username, password, description, identifier_id, issue_number):
    logging.debug(
        LOG_PREFIX + "Will send editIssue request for resolving to BMC FootPrints v11 Web Service API: " + url + ".")
    headers = {'content-type': 'text/xml; charset=UTF-8'}
    body = '''
        <?xml version='1.0' encoding='UTF-8'?>
        <soap-env:Envelope
            xmlns:soap-env='http://schemas.xmlsoap.org/soap/envelope/'
            xmlns:SOAP-ENV='http://schemas.xmlsoap.org/soap/envelope/'
            xmlns:SOAP-ENC='http://schemas.xmlsoap.org/soap/encoding/'
            xmlns:namesp2='http://xml.apache.org/xml-soap'
            xmlns:xsd='http://www.w3.org/1999/XMLSchema'
            xmlns:xsi='http://www.w3.org/1999/XMLSchema-instance'>
            <soap-env:Header />
            <soap-env:Body>
                <namesp1:MRWebServices__editIssue
                    xmlns:namesp1='MRWebServices'>
                    <user xsi:type='xsd:string'>{0}</user>
                    <password xsi:type='xsd:string'>{1}</password>
                    <extrainfo xsi:type='xsd:string' />
                    <args xsi:type='namesp2:SOAPStruct'>
                        <status xsi:type='xsd:string'>Closed</status>
                        <description xsi:type='xsd:string'>{2}</description>
                        <projfields xsi:type='namesp2:SOAPStruct'>
                            <Closure__bCode xsi:type='xsd:string'>Completed__bSuccessfully</Closure__bCode>
                            <Resolution xsi:type='xsd:string'>{2}</Resolution>
                        </projfields>
                        <projectID xsi:type='xsd:int'>{3}</projectID>
                        <mrID xsi:type='xsd:int'>{4}</mrID>
                    </args>
                </namesp1:MRWebServices__editIssue>
            </soap-env:Body>
        </soap-env:Envelope>
        '''.format(username, password, description, identifier_id, issue_number)

    response = requests.post(url, data=body, headers=headers)

    logging.debug('Response from BMC FootPrints v11 Web Service API: ' + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")


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


def convert_priority(priority):
    if priority == 'P1':
        return '1'
    elif priority == 'P2':
        return '2'
    elif priority == 'P3':
        return '3'
    elif priority == 'P4':
        return '4'
    elif priority == 'P5':
        return '5'
    return '3'


def parse_from_queue_message(key):
    if key in queue_message.keys():
        return queue_message[key]
    return ""


def main():
    global LOG_PREFIX
    global BMC_FOOTPRINTS_WEB_SERVICE_EXTENSION
    print("QUEUE: " + queue_message_string)

    alert_id = queue_message['alert']['alertId']
    mapped_action = queue_message['params']['mappedActionV2']['name']
    issue_number = parse_from_queue_message('issueNumber')
    title = parse_from_queue_message('title')
    description = parse_from_queue_message('description')
    priority = parse_from_queue_message('priority')
    issue_type = parse_from_queue_message('issueType')
    alert_alias = parse_from_queue_message('alertAlias')

    BMC_FOOTPRINTS_WEB_SERVICE_EXTENSION = '/MRcgi/MRWebServices.pl'
    LOG_PREFIX = '[' + mapped_action + ']'
    logging.info('Will execute ' + mapped_action + ' for alertId ' + alert_id)

    url = parse_field('url', True)
    if url[-1] == '/':
        url = url[:-1] + BMC_FOOTPRINTS_WEB_SERVICE_EXTENSION
    else:
        url += BMC_FOOTPRINTS_WEB_SERVICE_EXTENSION
    username = parse_field('username', True)
    password = parse_field('password', True)
    incident_workspace_id = parse_field('incidentWorkspaceId', False)
    problem_workspace_id = parse_field('problemWorkspaceId', False)
    if not problem_workspace_id and not incident_workspace_id:
        logging.error(LOG_PREFIX + 'Cannot find both of the incidentWorkspaceId and problemWorkspaceId either in the '
                                   'configuration file or from the Opsgenie payload. Please fill one of the incident '
                                   'or problem workspace IDs in the config file or in the integration settings in '
                                   'Opsgenie.')
        return
    priority = convert_priority(priority)
    if mapped_action == 'createIncident':
        created_issue_number = create_issue(url, username, password, alert_alias, priority, description, title,
                                            incident_workspace_id)
        add_details(created_issue_number, alert_id)
    elif mapped_action == 'createProblem':
        created_issue_number = create_issue(url, username, password, alert_alias, priority, description, title,
                                            problem_workspace_id)
        add_details(created_issue_number, alert_id)
    else:
        if not issue_type:
            logging.error(LOG_PREFIX + 'Cannot obtain issueType from the Opsgenie payload. '
                                       'Please make sure your integrations settings are correct in Opsgenie.')
            return

        workspace_id = incident_workspace_id if 'Incident' == issue_type else problem_workspace_id

        if mapped_action == 'updateDescription':
            update_issue_description(url, username, password, description, workspace_id, issue_number)
        elif mapped_action == "updatePriority":
            update_issue_priority(url, username, password, priority, workspace_id, issue_number)
        elif mapped_action == "resolveIssue":
            resolve_issue(url, username, password, description, workspace_id, issue_number)
        else:
            logging.warning(LOG_PREFIX + "Skipping [" + mapped_action + "] action, could not determine the mapped "
                                                                        "action.")


if __name__ == '__main__':
    main()
