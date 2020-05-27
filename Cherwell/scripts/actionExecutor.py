import argparse
import json
import logging
import sys
from urllib import parse

import requests

CONNECTION = "connection"
HTTP_TIMEOUT = 30000

INCIDENT_TEMPLATE = "incidentTemplate"
INCIDENT_ID = "incidentId"
CUSTOMER_BUS_OBJ_ID = "customerId"
CUSTOMER_OG_ID = "customerId"
JOURNAL_ID = "journalId"
JOURNAL_NOTE_ID = "journalNoteId"
JOURNAL_TEMPLATE = "journalTemplate"
JOURNAL_RELATIONSHIP_ID = "journalRelationshipId"

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--payload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Level of log', required=True)
parser.add_argument('-httpTimeout', '--httpTimeout', help='Http timeout', required=False)

parser.add_argument('-username', '--username', help='Username', required=False)
parser.add_argument('-password', '--password', help='Password', required=False)
parser.add_argument('-apiUrl', '--apiUrl', help='API Url', required=False)
parser.add_argument('-clientId', '--clientId', help='Client Id', required=False)
args = vars(parser.parse_args())

queue_message_string = args.get('payload')
queue_message = json.loads(queue_message_string)

username = ''
password = ''
api_url = ''
client_id = ''
access_token = ''

alert = queue_message.get("alert")
alert_id = alert.get("alertId")
mapped_action = str(queue_message.get("mappedActionV2").get("name"))
LOG_PREFIX = "[" + mapped_action + "]"

logging.basicConfig(stream=sys.stdout, level=args.get('logLevel'))


class MemoryStore:
    memory_store = {}

    @staticmethod
    def store(key, value):
        MemoryStore.memory_store[key] = value

    @staticmethod
    def lookup(key):
        return MemoryStore.memory_store.get(key)

    @staticmethod
    def remove(key):
        MemoryStore.memory_store.pop(key, None)

    @staticmethod
    def reset():
        MemoryStore.memory_store = {}


class BusinessObjectField:
    def __init__(self, dirty, displayName, fieldId, name, value):
        self.dirty = dirty
        self.displayName = displayName
        self.fieldId = fieldId
        self.name = name
        self.value = value


class Condition:
    def __init__(self, fieldId, operator, value):
        self.fieldId = fieldId
        self.operator = operator
        self.value = value

def parse_field(key, mandatory):
    variable = queue_message.get(key)
    if variable is None or not variable.strip():
        variable = args.get(key)
    if mandatory and not variable:
        err_message = LOG_PREFIX + " Skipping action, Mandatory conf item " + key + \
                  " is missing. Check your configuration file."
        logging.warning(err_message)
        raise ValueError(err_message)
    return variable


def parse_field_if_null_or_empty(property, property_key):
    if property is None or "" == property:
        return parse_field(property_key, True)
    else:
        return property


def parse_parameters():
    global username
    global password
    global api_url
    global client_id
    username = parse_field_if_null_or_empty(username, 'username')
    logging.debug('Username: ' + username)
    password = parse_field_if_null_or_empty(password, 'password')
    logging.debug('Password: ' + password)
    api_url = parse_field_if_null_or_empty(api_url, 'apiUrl')
    logging.debug('API URL: ' + api_url)
    client_id = parse_field_if_null_or_empty(client_id, 'clientId')
    logging.debug('Client ID: ' + client_id)


def get_description():
    description = queue_message.get("description")
    if not description.strip():
        description = '-'
    alias = queue_message.get("alias")
    return description + '\nog_alias:[' + alias + ']'


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


def login():
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'}
    params = {
        'grant_type': 'password',
        'client_id': parse.quote(client_id, safe=''),
        'username': username,
        'password': password}

    response = requests.post(api_url + '/token', data=params, headers=headers, timeout=HTTP_TIMEOUT)
    if response.json():
        response_body = response.json()
        if response.status_code < 300 and response_body.get('access_token'):
            logging.info(LOG_PREFIX + ' Successfully logged in.')
            logging.debug(LOG_PREFIX + ' Cherwell response: ' + str(response.content))
            return response_body.get('access_token')
    err_message = LOG_PREFIX + ' Could not log in; response: ' + str(response.status_code) + " " + str(response.content)
    logging.error(err_message)
    raise Exception(err_message)


def create_headers():
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': "Bearer " + access_token}
    return headers


def add_details(bus_ob_public_id):
    endpoint = args.get('opsgenieUrl') + '/v2/alerts/' + alert_id + '/details'
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'GenieKey ' + args.get('apiKey')
    }
    body = {
        'details': {
            'og-internal-incidentId': bus_ob_public_id
        }
    }
    r = requests.post(endpoint, json=body, headers=headers)
    logging.debug(LOG_PREFIX + 'Add details result ' + str(r.content) + ' Status code: ' + str(r.status_code) +
                  ("Reason: " + str(r.reason)) if str(r.reason) else "")


def create_incident():
    headers = create_headers()

    incident_bus_ob_id = get_bus_ob_id('Incident', INCIDENT_ID)
    customer_id_field_id = get_field_id(incident_bus_ob_id, INCIDENT_TEMPLATE, 'Customer ID')
    description_field_id = get_field_id(incident_bus_ob_id, INCIDENT_TEMPLATE, 'Description')
    priority_field_id = get_field_id(incident_bus_ob_id, INCIDENT_TEMPLATE, 'Priority')
    short_description_field_id = get_field_id(incident_bus_ob_id, INCIDENT_TEMPLATE, 'Short Description')
    owned_by_description_field_id = get_field_id(incident_bus_ob_id, INCIDENT_TEMPLATE, 'Owned By')

    fields = []
    fields.append(BusinessObjectField(dirty=True, displayName='Description', fieldId=description_field_id, name='Description', value=get_description()).__dict__)
    fields.append(BusinessObjectField(dirty=True, displayName='Priority', fieldId=priority_field_id, name='Priority', value=convert_priority(queue_message.get('priority'))).__dict__)
    fields.append(BusinessObjectField(dirty=True, displayName='Customer ID', fieldId=customer_id_field_id, name='CustomerRecID', value=get_og_customer_id()).__dict__)
    fields.append(BusinessObjectField(dirty=True, displayName='Short Description', fieldId=short_description_field_id, name='ShortDescription', value=queue_message.get('err_message')).__dict__)
    fields.append(BusinessObjectField(dirty=True, displayName='Owned By', fieldId=owned_by_description_field_id, name='OwnedBy', value='OpsGenie').__dict__)

    payload = {
        'busObId': incident_bus_ob_id,
        'fields': fields,
        'persist': True
    }

    logging.debug("Incident creation payload:" + json.dumps(payload))

    response = requests.post(api_url + '/api/V1/savebusinessobject/', data=json.dumps(payload), headers=headers, timeout=HTTP_TIMEOUT)
    if response.json():
        response_body = response.json()
        if response.status_code < 300 and response_body.get('busObPublicId'):
            logging.info(LOG_PREFIX + " Successfully created incident.")
            logging.debug(LOG_PREFIX + " Cherwell response: " + str(response.content))
            add_details(response_body.get('busObPublicId'))
            return
    err_message = LOG_PREFIX + " Could not create incident; response: " + str(response.status_code) + " " + str(response.content)
    logging.error(err_message)
    raise Exception(err_message)


def set_incident_status(status):
    headers = create_headers()

    incident_bus_ob_id = get_bus_ob_id('Incident', INCIDENT_ID)
    status_field_id = get_field_id(incident_bus_ob_id, INCIDENT_TEMPLATE, 'Status')

    fields = []
    fields.append(BusinessObjectField(dirty=True, displayName='Status', fieldId=status_field_id, name='Status', value=status).__dict__)
    if not incident_has_owner(queue_message.get('incidentPublicId')):
        owned_by_description_field_id = get_field_id(incident_bus_ob_id, INCIDENT_TEMPLATE, 'Owned By')
        fields.append(BusinessObjectField(dirty=True, displayName='Owned By', fieldId=owned_by_description_field_id, name='Owned By', value='OpsGenie').__dict__)

    payload = {
        'busObId': incident_bus_ob_id,
        'busObPublicId': queue_message.get('incidentPublicId'),
        'fields': fields
    }

    logging.debug("Incident modify payload:" + json.dumps(payload))

    response = requests.post(api_url + '/api/V1/savebusinessobject/', data=json.dumps(payload), headers=headers, timeout=HTTP_TIMEOUT)
    if response.json():
        response_body = response.json()
        if response.status_code < 300 and response_body.get('busObPublicId'):
            logging.info(LOG_PREFIX + " Successfully modified incident.")
            logging.debug(LOG_PREFIX + " Cherwell response: " + str(response.content))
            return
    err_message = LOG_PREFIX + " Could not modify incident; response: " + str(response.status_code) + " " + str(response.content)
    logging.error(err_message)
    raise Exception(err_message)


def add_journal_to_incident():
    headers = create_headers()

    journal_bus_ob_id = get_bus_ob_id('Journal', JOURNAL_ID)
    journal_note_bus_ob_id = get_journal_note_bus_id()
    journal_type_id_field_id = get_field_id(journal_bus_ob_id, JOURNAL_TEMPLATE, 'Journal TypeID')
    journal_details_field_id = get_field_id(journal_bus_ob_id, JOURNAL_TEMPLATE, 'Details')
    incident_journal_relationship_id = get_incident_journal_relationship_id()

    fields = []
    fields.append(BusinessObjectField(dirty=True, displayName='Journal TypeID', fieldId=journal_type_id_field_id, name='JournalTypeID', value=journal_note_bus_ob_id).__dict__)
    fields.append(BusinessObjectField(dirty=True, displayName='Details', fieldId=journal_details_field_id, name='Details', value=queue_message.get('journalNote')).__dict__)

    payload = {}
    payload['fields'] = fields
    payload['parentBusObId'] = get_bus_ob_id('Incident', INCIDENT_ID)
    payload['parentBusObPublicId'] = queue_message.get('incidentPublicId')
    payload['relationshipId'] = incident_journal_relationship_id
    payload['busObId'] = journal_bus_ob_id
    payload['persist'] = True

    logging.debug("Add journal payload:" + json.dumps(payload))

    response = requests.post(api_url + '/api/V1/saverelatedbusinessobject/', data=json.dumps(payload), headers=headers, timeout=HTTP_TIMEOUT)
    if response.json():
        response_body = response.json()
        if response.status_code < 300 and response_body.get('busObPublicId'):
            logging.info(LOG_PREFIX + " Successfully added journal to incident with public id: " + queue_message.get('incidentPublicId'))
            logging.debug(LOG_PREFIX + " Cherwell response: " + str(response.content))
            return
    err_message = LOG_PREFIX + " Could not add journal to incident; response: " + str(response.status_code) + " " + str(response.content)
    logging.error(err_message)
    raise Exception(err_message)


def get_bus_ob_id(object_name, store_key):
    bus_ob_id = MemoryStore.lookup(store_key)
    if not bus_ob_id:
        bus_ob_id = retrieve_bus_ob_id(object_name, store_key)
    return bus_ob_id


def retrieve_bus_ob_id(object_name, store_key):
    headers = create_headers()
    response = requests.get(api_url + '/api/V1/getbusinessobjectsummary/busobname/' + object_name, headers=headers, timeout=HTTP_TIMEOUT)
    if response.json():
        logging.error(response)
        response_body = response.json()
        if response.status_code < 300 and response_body[0] and response_body[0].get('busObId'):
            bus_ob_id = response_body[0].get('busObId')
            logging.debug("Successfully retrieved " + object_name + "'s busObId: " + bus_ob_id)
            MemoryStore.store(store_key, bus_ob_id)
            return bus_ob_id
    err_message = LOG_PREFIX + " Could not acquire " + object_name + " business object ID; response: " + str(response.status_code) + " " + str(response.content)
    logging.error(err_message)
    raise Exception(err_message)


def get_template(bus_ob_id, store_key):
    template = MemoryStore.lookup(store_key)
    if not template:
        template = retrieve_template(bus_ob_id, store_key)
    return template


def retrieve_template(bus_ob_id, store_key):
    headers = create_headers()
    post_params = {}
    post_params['busObId'] = bus_ob_id
    post_params['includeAll'] = True
    logging.debug("Will retrieve " + bus_ob_id + "'s template with payload: " + json.dumps(post_params))

    response = requests.post(api_url + '/api/V1/getbusinessobjecttemplate/', data=json.dumps(post_params), headers=headers, timeout=HTTP_TIMEOUT)
    if response.json():
        response_body = response.json()
        if response.status_code < 300 and response_body.get('fields'):
            fields = response_body.get('fields')
            logging.debug("Successfully retrieved " + bus_ob_id + "s template: " + str(fields))
            MemoryStore.store(store_key, fields)
            return fields
    err_message = LOG_PREFIX + " Could not acquire " + store_key + "; response: " + str(response.status_code) + " " + str(response.content)
    logging.error(err_message)
    raise Exception(err_message)


def get_field_id(bus_ob_id, template_store_key, display_name):
    templates = get_template(bus_ob_id, template_store_key)
    field = None
    for template in templates:
        if template.get('displayName') == display_name:
            field = template
            break
    if field:
        field_id = field.get('fieldId')
        logging.debug("Found FieldId with displayName: " + display_name + " fieldId:" + field_id)
        return field_id
    else:
        err_message = LOG_PREFIX + " Could not find fieldId with displayName: " + display_name
        logging.error(err_message)
        raise Exception(err_message)


def get_og_customer_id():
    og_customer_id = MemoryStore.lookup(CUSTOMER_OG_ID)
    if not og_customer_id:
        og_customer_id = retrieve_og_customer_id()
    return og_customer_id


def retrieve_og_customer_id():
    customer_bus_ob_id = get_bus_ob_id('CustomerInternal', CUSTOMER_BUS_OBJ_ID)
    headers = create_headers()

    query_params = {
        'includerelationships': True
    }
    response = requests.get(api_url + '/api/V1/getbusinessobjectschema/busobid/' + customer_bus_ob_id, params=query_params, headers=headers, timeout=HTTP_TIMEOUT)
    if response.json():
        response_body = response.json()
        if response.status_code < 300 and response_body.get('fieldDefinitions'):
            full_name_field_map = None
            for field_definition in response_body.get('fieldDefinitions'):
                if field_definition.get('displayName') == 'Full name':
                    full_name_field_map = field_definition
                    break
            if full_name_field_map:
                full_name_field_id = full_name_field_map.get('fieldId')
                logging.debug("Successfully retrieved customer's FullNameFieldID: " + full_name_field_id)
            else:
                err_message = LOG_PREFIX + " Could not retrieve customer's FullNameFieldID"
                logging.error(err_message)
                raise Exception(err_message)

            search_payload = {}
            search_payload['busObId'] = customer_bus_ob_id
            search_payload['filters'] = [Condition(fieldId=full_name_field_id, operator='eq', value='OpsGenie').__dict__]
            search_payload['includeAllFields'] = True

            search_response = requests.post(api_url + '/api/V1/getsearchresults', data=json.dumps(search_payload), headers=headers, timeout=HTTP_TIMEOUT)
            if search_response.json():
                search_response_body = search_response.json()
                search_response_business_objects = search_response_body.get('businessObjects')
                if search_response_business_objects and search_response_business_objects[0]:
                    og_cust_bus_ob_rec_id = search_response_business_objects[0].get('busObRecId')
                    if search_response.status_code < 300 and og_cust_bus_ob_rec_id:
                        MemoryStore.store(CUSTOMER_OG_ID, og_cust_bus_ob_rec_id)
                        logging.debug("Found internal customer named 'OpsGenie' busObRecId: " + og_cust_bus_ob_rec_id)
                        return og_cust_bus_ob_rec_id
            err_message = LOG_PREFIX + " Could not find internal customer named 'OpsGenie'"
            logging.error(err_message)
            raise Exception(err_message)
    err_message = LOG_PREFIX + " Could not acquire business object schema of " + customer_bus_ob_id + "; response: " + str(response.status_code) + " " + str(response.content)
    logging.error(err_message)
    raise Exception(err_message)


def get_journal_note_bus_id():
    journal_note_bus_id = MemoryStore.lookup(JOURNAL_NOTE_ID)
    if not journal_note_bus_id:
        journal_note_bus_id = retrieve_journal_note_bus_ob_id()
    return journal_note_bus_id


def retrieve_journal_note_bus_ob_id():
    headers = create_headers()
    response = requests.get(api_url + '/api/V1/getbusinessobjectsummary/busobname/Journal', headers=headers, timeout=HTTP_TIMEOUT)
    if response.json():
        response_body = response.json()
        if response.status_code < 300 and response_body[0] and response_body[0].get('groupSummaries'):
            journal_note = None
            for group_summary in response_body[0].get('groupSummaries'):
                if group_summary.get('displayName') == 'Journal - Note':
                    journal_note = group_summary
                    break
            if journal_note is not None:
                bus_ob_id = journal_note.get('busObId')
                logging.debug("Successfully retrieved Journal - Note's busObId: " + bus_ob_id)
                MemoryStore.store(JOURNAL_NOTE_ID, bus_ob_id)
                return bus_ob_id
    err_message = LOG_PREFIX + " Could not acquire Journal - Note's business object ID; response: " + str(response.status_code) + " " + str(response.content)
    logging.error(err_message)
    raise Exception(err_message)


def get_incident_journal_relationship_id():
    relationship_id = MemoryStore.lookup(JOURNAL_RELATIONSHIP_ID)
    if not relationship_id:
        relationship_id = retrieve_incident_journal_relationship_id()
    return relationship_id


def retrieve_incident_journal_relationship_id():
    headers = create_headers()
    query_params = {
        'includerelationships': True
    }
    response = requests.get(api_url + '/api/V1/getbusinessobjectschema/busobid/' + get_bus_ob_id('Incident', INCIDENT_ID), params=query_params, headers=headers, timeout=HTTP_TIMEOUT)
    if response.json():
        response_body = response.json()
        if response.status_code < 300 and response_body.get('relationships'):
            incident_owns_journals = {}
            for relationship in response_body.get('relationships'):
                if relationship.get('displayName') == 'Incident Owns Journals':
                    incident_owns_journals = relationship
                    break
            if incident_owns_journals:
                relationship_id = incident_owns_journals.get('relationshipId')
                logging.debug("Successfully retrieved Incident owns Journals's relationship ID: " + relationship_id)
                MemoryStore.store(JOURNAL_RELATIONSHIP_ID, relationship_id)
                return relationship_id
    err_message = LOG_PREFIX + " Could not acquire Incident owns Journals's relationship ID; response: " + str(response.status_code) + " " + str(response.content)
    logging.error(err_message)
    raise Exception(err_message)


def incident_has_owner(incident_public_id):
    headers = create_headers()
    response = requests.get(api_url + '/api/V1/getbusinessobject/busobid/' + get_bus_ob_id('Incident', INCIDENT_ID) +
                            '/publicid/' + incident_public_id, headers=headers, timeout=HTTP_TIMEOUT)
    if response.json():
        response_body = response.json()
        if response.status_code < 300 and response_body.get('fields'):
            owned_by_field = None
            for field in response_body.get('fields'):
                if field.get('displayName') == 'Owned By':
                    owned_by_field = field
                    break
            if owned_by_field:
                return not (owned_by_field.get('value') is None or owned_by_field.get('value') == '')
    err_message = LOG_PREFIX + " Could not acquire Incident's ownership information; response: " + str(response.status_code) + " " + str(response.content)
    logging.error(err_message)
    raise Exception(err_message)


def main():
    global HTTP_TIMEOUT
    global access_token

    timeout = parse_field("httpTimeout", False)
    if timeout:
        HTTP_TIMEOUT = timeout

    logging.info("Will execute " + mapped_action + " for alertId " + alert_id)

    try:
        parse_parameters()
        access_token = login()

        if mapped_action == 'addJournal':
            add_journal_to_incident()
        elif mapped_action == 'createIncident':
            create_incident()
        elif mapped_action == 'resolveIncident':
            set_incident_status('Resolved')
        elif mapped_action == 'inProgressIncident':
            set_incident_status('In Progress')
    except Exception as e:
        logging.error(LOG_PREFIX + " " + format(e))


if __name__ == '__main__':
    main()
