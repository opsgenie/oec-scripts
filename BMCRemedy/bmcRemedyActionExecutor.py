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
parser.add_argument('-url', '--url', help='Url', required=False)
parser.add_argument('-username', '--username', help='Username', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
parser.add_argument('-midtierServerUrl', '--midtierServerUrl', help='MidTier Server Url', required=False)
parser.add_argument('-serverName', '--serverName', help='Server name', required=False)

args = vars(parser.parse_args())

queue_message_string = args['payload']
queue_message = json.loads(queue_message_string)

logging.basicConfig(stream=sys.stdout, level=args['logLevel'])


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
    logging.debug(LOG_PREFIX + 'Add details result ' + str(r.content) + ' Status code: ' + str(r.status_code) +
                  ("Reason: " + str(r.reason)) if r.reason else "")


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
    body = \
        '''<?xml version='1.0' encoding='UTF-8'?>
            <soapenv:Envelope
                xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
                xmlns:urn='urn:HPD_IncidentServiceInterface'>
                <soapenv:Header>
                    <AuthenticationInfo>
                        <userName>{0}</userName>
                        <urn:password>{1}</urn:password>
                    </AuthenticationInfo>
                </soapenv:Header>
                <soapenv:Body>
                    <Process_Event>
                        <Action>PROCESS_EVENT</Action>
                        <Incident_Number>{2}</Incident_Number>
                        <Work_Info_Details>{3}</Work_Info_Details>
                    </Process_Event>
                </soapenv:Body>
            </soapenv:Envelope>'''.format(username, password, incident_number, work_info_details)
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
    body = \
        '''<?xml version='1.0' encoding='UTF-8'?>
            <soapenv:Envelope
                xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
                xmlns:urn='urn:HPD_IncidentInterface_Create_WS'>
                <soapenv:Header>
                    <AuthenticationInfo>
                        <userName>{0}</userName>
                        <urn:password>{1}</urn:password>
                    </AuthenticationInfo>
                </soapenv:Header>
                <soapenv:Body>
                    <HelpDesk_Submit_Service>
                        <Company>{2}</Company>
                        <First_Name>{3}</First_Name>
                        <Last_Name>{4}</Last_Name>
                        <Impact>{5}</Impact>
                        <Reported_Source>{6}</Reported_Source>
                        <Service_Type>{7}</Service_Type>
                        <Status>New</Status>
                        <Summary>{8}</Summary>
                        <Urgency>{9}</Urgency>
                        <Notes>{10}</Notes>
                        <Assigned_Group>{11}</Assigned_Group>
                        <Assignee>{12}</Assignee>
                        <Action></Action>
                    </HelpDesk_Submit_Service>
                </soapenv:Body>
            </soapenv:Envelope>'''.format(username, password, company, customer_name, customer_last_name,
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

    body = \
        '''<?xml version='1.0' encoding='UTF-8'?>
            <soapenv:Envelope
                xmlns:soapenv='http://schemas.xmlsoap.org/soap/envelope/'
                xmlns:urn='urn:HPD_IncidentInterface_WS'>
                <soapenv:Header>
                    <AuthenticationInfo>
                        <userName>{0}</userName>
                        <urn:password>{1}</urn:password>
                    </AuthenticationInfo>
                </soapenv:Header>
                <soapenv:Body>
                    <HelpDesk_Modify_Service>
                        <Company>{2}</Company>
                        <Impact>{3}</Impact>
                        <Incident_Number>{4}</Incident_Number>
                        <Service_Type>{5}</Service_Type>
                        <Status>Closed</Status>
                        <Summary>{6}</Summary>
                        <Urgency>{7}</Urgency>
                        <Notes>{8}</Notes>
                        <Resolution>{9}</Resolution>
                        <Action></Action>
                        <Categorization_Tier_1></Categorization_Tier_1>
                        <Categorization_Tier_2></Categorization_Tier_2>
                        <Categorization_Tier_3></Categorization_Tier_3>
                        <Manufacturer></Manufacturer>
                        <Closure_Manufacturer></Closure_Manufacturer>
                        <Closure_Product_Category_Tier1></Closure_Product_Category_Tier1>
                        <Closure_Product_Category_Tier2></Closure_Product_Category_Tier2>
                        <Closure_Product_Category_Tier3></Closure_Product_Category_Tier3>
                        <Closure_Product_Model_Version></Closure_Product_Model_Version>
                        <Closure_Product_Name></Closure_Product_Name>
                        <Product_Categorization_Tier_1></Product_Categorization_Tier_1>
                        <Product_Categorization_Tier_2></Product_Categorization_Tier_2>
                        <Product_Categorization_Tier_3></Product_Categorization_Tier_3>
                        <Product_Model_Version></Product_Model_Version>
                        <Product_Name></Product_Name>
                        <Reported_Source></Reported_Source>
                        <Resolution_Category></Resolution_Category>
                        <Resolution_Category_Tier_2></Resolution_Category_Tier_2>
                        <Resolution_Category_Tier_3></Resolution_Category_Tier_3>
                        <Resolution_Method></Resolution_Method>
                        <Work_Info_Summary></Work_Info_Summary>
                        <Work_Info_Notes></Work_Info_Notes>
                        <Work_Info_Type></Work_Info_Type>
                        <Work_Info_Date></Work_Info_Date>
                        <Work_Info_Source></Work_Info_Source>
                        <Work_Info_Locked></Work_Info_Locked>
                        <Work_Info_View_Access></Work_Info_View_Access>
                        <ServiceCI></ServiceCI>
                        <ServiceCI_ReconID></ServiceCI_ReconID>
                        <HPD_CI></HPD_CI>
                        <HPD_CI_ReconID></HPD_CI_ReconID>
                        <HPD_CI_FormName></HPD_CI_FormName>
                        <z1D_CI_FormName></z1D_CI_FormName>
                    </HelpDesk_Modify_Service>
                </soapenv:Body>
            </soapenv:Envelope>'''.format(username, password, company, impact, incident_number,
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

    mapped_action = queue_message['mappedActionV2']['name']
    alert_id = queue_message['alert']['alertId']
    incident_number = queue_message.get('incidentNumber')
    work_info_details = queue_message.get('workInfoDetails')
    assigned_group = queue_message.get('teamName')
    resolution = queue_message.get('resolution')
    message = queue_message.get('message')
    notes = 'og_alias:[' + str(queue_message.get('alias')) + ']'
    priority = queue_message.get('priority')
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
        assigned_group = 'Service Desk'
        assignee = 'Allen Allbrook'

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
