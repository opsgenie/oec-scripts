import argparse
import json
import logging
import sys

import requests

parser = argparse.ArgumentParser()
parser.add_argument('-queuePayload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-loglevel', '--loglevel', help='Level of log', required=True)
parser.add_argument('-url', '--url', help='Url', required=False)
parser.add_argument('-username', '--username', help='Username', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
parser.add_argument('-midtierServerUrl', '--midtierServerUrl', help='MidTier Server Url', required=False)
parser.add_argument('-serverName', '--serverName', help='Server name', required=False)

args = vars(parser.parse_args())

queue_message_string = args['queuePayload']
queue_message = json.loads(queue_message_string)

logging.basicConfig(stream=sys.stdout, level=args['loglevel'])


def add_details(body, alert_id):
    endpoint = args['opsgenieUrl'] + '/v2/alerts/' + alert_id + '/details'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'GenieKey ' + args['apiKey']
    }
    body = {
        'details': {
            'og-internal-incidentID': body
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


def priority_to_impact(priority):
    if priority == 'P1':
        return '1-Extensive/Widespread'
    elif priority == 'P2':
        return '2-Significant'
    elif priority == 'P3':
        return '3-Moderate/Limited'
    return '4-Minor'


def priority_to_urgency(priority):
    if priority == 'P1':
        return '1-Critical'
    elif priority == 'P2':
        return '2-High'
    elif priority == 'P3':
        return '3-Medium'
    return '4-Low'


def add_work_info(soap_action, username, password, incident_number, work_info_details, midtier_server_url, server_name):
    endpoint = midtier_server_url + "/arsys/services/ARService?server=" + server_name \
               + "&webService=HPD_IncidentServiceInterface"
    logging.debug("SOAP Endpoint: " + endpoint)

    headers = {'content-type': 'text/xml; charset=UTF-8',
               'Soapaction': soap_action}
    body = '''
        <?xml version='1.0' encoding='UTF-8'?>
        <soapenv:Envelope
            xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
            xmlns:urn='urn:HPD_IncidentServiceInterface'>
            <soapenv:Header>
                <urn:AuthenticationInfo>
                    <urn:userName>{0}</urn:userName>
                    <urn:password>{1}</urn:password>
                </urn:AuthenticationInfo>
            </soapenv:Header>
            <soapenv:Body>
                <urn:Process_Event>
                    <urn:Action>PROCESS_EVENT</urn:Action>
                    <urn:Incident_Number>{2}</urn:Incident_Number>
                    <urn:Work_Info_Details>{3}</urn:Work_Info_Details>
                </urn:Process_Event>
            </soapenv:Body>
        </soapenv:Envelope>
    '''.format(username, password, incident_number, work_info_details)
    response = requests.post(endpoint, data=body, headers=headers)

    logging.debug("Response from BMC Remedy: " + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")


def create_incident(soap_action, alert_id, username, password, company, customer_name, customer_last_name,
                    impact, reported_source, incident_type, message,
                    urgency, notes, assigned_group, assignee, midtier_server_url, server_name):
    endpoint = midtier_server_url + "/arsys/services/ARService?server=" + \
               server_name + "&webService=HPD_IncidentInterface_Create_WS"
    logging.debug("SOAP Endpoint: " + endpoint)

    headers = {'content-type': 'text/xml; charset=UTF-8',
               'Soapaction': soap_action}
    body = '''
        <?xml version='1.0' encoding='UTF-8'?>
        <soapenv:Envelope
            xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
            xmlns:urn='urn:HPD_IncidentInterface_Create_WS'>
            <soapenv:Header>
                <urn:AuthenticationInfo>
                    <urn:userName>{0}</urn:userName>
                    <urn:password>{1}</urn:password>
                </urn:AuthenticationInfo>
            </soapenv:Header>
            <soapenv:Body>
                <urn:HelpDesk_Submit_Service>
                    <urn:Company>{2}</urn:Company>
                    <urn:First_Name>{3}</urn:First_Name>
                    <urn:Last_Name>{4}</urn:Last_Name>
                    <urn:Impact>{5}</urn:Impact>
                    <urn:Reported_Source>{6}</urn:Reported_Source>
                    <urn:Service_Type>{7}</urn:Service_Type>
                    <urn:Status>Create</urn:Status>
                    <urn:Summary>{8}</urn:Summary>
                    <urn:Urgency>{9}</urn:Urgency>
                    <urn:Notes>{10}</urn:Notes>
                    <urn:Assigned_Group>{11}</urn:Assigned_Group>
                    <urn:Assignee>{12}</urn:Assignee>
                    <urn:Action></urn:Action>
                </urn:HelpDesk_Submit_Service>
            </soapenv:Body>
        </soapenv:Envelope>
    '''.format(username, password, company, customer_name, customer_last_name,
               impact, reported_source, incident_type, message,
               urgency, notes, assigned_group, assignee)

    response = requests.post(endpoint, data=body, headers=headers)

    logging.debug("Response from BMC Remedy: " + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")
    if response.status_code > 299:
        add_details(response.content, alert_id)


def close_incident(soap_action, username, password, company, impact, incident_number, service_type,
                   summary, urgency, notes, resolution, midtier_server_url, server_name):
    endpoint = midtier_server_url + "/arsys/services/ARService?server=" \
               + server_name + "&webService=HPD_IncidentInterface_WS"
    logging.debug("SOAP Endpoint: " + endpoint)

    headers = {'content-type': 'text/xml; charset=UTF-8',
               'Soapaction': soap_action}

    body = '''
    <?xml version='1.0' encoding='UTF-8'?>
    <soapenv:Envelope
        xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
        xmlns:urn='urn:HPD_IncidentInterface_WS'>
        <soapenv:Header>
            <urn:AuthenticationInfo>
                <urn:userName>{0}</urn:userName>
                <urn:password>{1}</urn:password>
            </urn:AuthenticationInfo>
        </soapenv:Header>
        <soapenv:Body>
            <urn:HelpDesk_Modify_Service>
                <urn:Company>{2}</urn:Company>
                <urn:Impact>{3}</urn:Impact>
                <urn:Incident_Number>{4}</urn:Incident_Number>
                <urn:Service_Type>{5}</urn:Service_Type>
                <urn:Status>Close</urn:Status>
                <urn:Summary>{6}</urn:Summary>
                <urn:Urgency>{7}</urn:Urgency>
                <urn:Notes>{8}</urn:Notes>
                <urn:Resolution>{9}</urn:Resolution>
                <urn:Action></urn:Action>
                <urn:Categorization_Tier_1></urn:Categorization_Tier_1>
                <urn:Categorization_Tier_2></urn:Categorization_Tier_2>
                <urn:Categorization_Tier_3></urn:Categorization_Tier_3>
                <urn:Manufacturer></urn:Manufacturer>
                <urn:Closure_Manufacturer></urn:Closure_Manufacturer>
                <urn:Closure_Product_Category_Tier1></urn:Closure_Product_Category_Tier1>
                <urn:Closure_Product_Category_Tier2></urn:Closure_Product_Category_Tier2>
                <urn:Closure_Product_Category_Tier3></urn:Closure_Product_Category_Tier3>
                <urn:Closure_Product_Model_Version></urn:Closure_Product_Model_Version>
                <urn:Closure_Product_Name></urn:Closure_Product_Name>
                <urn:Product_Categorization_Tier_1></urn:Product_Categorization_Tier_1>
                <urn:Product_Categorization_Tier_2></urn:Product_Categorization_Tier_2>
                <urn:Product_Categorization_Tier_3></urn:Product_Categorization_Tier_3>
                <urn:Product_Model_Version></urn:Product_Model_Version>
                <urn:Product_Name></urn:Product_Name>
                <urn:Reported_Source></urn:Reported_Source>
                <urn:Resolution_Category></urn:Resolution_Category>
                <urn:Resolution_Category_Tier_2></urn:Resolution_Category_Tier_2>
                <urn:Resolution_Category_Tier_3></urn:Resolution_Category_Tier_3>
                <urn:Resolution_Method></urn:Resolution_Method>
                <urn:Work_Info_Summary></urn:Work_Info_Summary>
                <urn:Work_Info_Notes></urn:Work_Info_Notes>
                <urn:Work_Info_Type></urn:Work_Info_Type>
                <urn:Work_Info_Date></urn:Work_Info_Date>
                <urn:Work_Info_Source></urn:Work_Info_Source>
                <urn:Work_Info_Locked></urn:Work_Info_Locked>
                <urn:Work_Info_View_Access></urn:Work_Info_View_Access>
                <urn:ServiceCI></urn:ServiceCI>
                <urn:ServiceCI_ReconID></urn:ServiceCI_ReconID>
                <urn:HPD_CI></urn:HPD_CI>
                <urn:HPD_CI_ReconID></urn:HPD_CI_ReconID>
                <urn:HPD_CI_FormName></urn:HPD_CI_FormName>
                <urn:z1D_CI_FormName></urn:z1D_CI_FormName>
            </urn:HelpDesk_Modify_Service>
        </soapenv:Body>
    </soapenv:Envelope>
    '''.format(username, password, company, impact, incident_number,
               service_type, summary, urgency, notes, resolution)

    response = requests.post(endpoint, data=body, headers=headers)

    logging.debug("Response from BMC Remedy: " + str(response.content) + " Response Code: "
                  + str(response.status_code) + (" Reason: " + str(response.reason)) if response.reason else "")


def main():
    global LOG_PREFIX

    username = parse_field('username', True)
    password = parse_field('password', True)
    midtier_server_url = parse_field('midtierServerUrl', False)
    server_name = parse_field('serverName', False)

    mapped_action = queue_message['mappedAction']['name']
    alert_id = queue_message['alert']['alertId']
    incident_number = queue_message['incidentNumber']
    work_info_details = queue_message['workInfoDetails']
    assigned_group = queue_message['teamName']
    resolution = queue_message['resolution']
    message = queue_message['message']
    notes = 'og_alias:[' + queue_message['alias'] + ']'
    priority = queue_message['priority']
    impact = priority_to_impact(priority)
    urgency = priority_to_urgency(priority)
    customer_name = 'App'
    customer_last_name = 'Admin'
    company = 'Calbro Services'
    incident_type = 'Infrastructure Event'
    reported_source = 'Other'
    assignee = ''

    LOG_PREFIX = '[' + mapped_action + ']'

    if not assigned_group:
        assigned_group = ''
        assignee = ''

    if mapped_action == 'addWorkInfo':
        add_work_info('SOAP-OpsGenie [Add Work Info]', username, password, incident_number,
                      work_info_details, midtier_server_url, server_name)
    elif mapped_action == 'createIncident':
        create_incident('SOAP-OpsGenie [Create Incident]', alert_id, username, password, company, customer_name,
                        customer_last_name, impact, reported_source, incident_type, message, urgency,
                        notes, assigned_group, assignee, midtier_server_url, server_name)
    elif mapped_action == 'closeIncident':
        close_incident('SOAP-OpsGenie [Close Incident]', username, password, company, impact, incident_number,
                       incident_type, message, urgency, notes, resolution, midtier_server_url,
                       server_name)
    else:
        logging.warning(LOG_PREFIX + "Skipping" + mapped_action + "action, could not determine the mapped action.")


if __name__ == '__main__':
    main()
