import argparse
import json
import logging
import os
import sys
import time
import zipfile

import html
import requests
from requests.auth import HTTPBasicAuth

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Level of log', required=True)
parser.add_argument('-api_url', '--api_url', help='Icinga Server URL', required=False)
parser.add_argument('-graphite_url', '--graphite_url', help='Graphite URL', required=False)
parser.add_argument('-user', '--user', help='User', required=True)
parser.add_argument('-password', '--password', help='Password', required=True)
parser.add_argument('-timeout', '--timeout', help='HTTP Timeout', required=False)
parser.add_argument('-expire_acknowledgement_after', '-expire_acknowledgement_after',
                    help='Removes acknowledgement after given value (in minutes.)', required=False)
parser.add_argument('-insecure', '--insecure', help='Skip verifying SSL certificate', required=False)

args = vars(parser.parse_args())

queue_message_string = args['queuePayload']
queue_message = json.loads(queue_message_string)

logging.basicConfig(stream=sys.stdout, level=args['logLevel'])


DIR_PATH = os.path.dirname(os.path.realpath(__file__))

def parse_field(key, mandatory):
    variable = queue_message[key]
    if not variable.strip():
        variable = args[key]
    if mandatory and not variable:
        raise ValueError(LOG_PREFIX + " Skipping action, Mandatory conf item '" + key +
                         "' is missing. Check your configuration file.")


def send_create_request(is_service_alert):
    attach(is_service_alert)


def post_to_icingaApi(url_path, content_map):
    url = args["api_url"] + url_path
    logging.debug(LOG_PREFIX + " Posting to Icinga. Url " + url + ", content: " + str(content_map))

    headers = {
        "Accept": "application/json"
    }

    verify_ssl = verify=False if args['insecure'] == 'true' else True
    response = requests.post(url, json=content_map, timeout=HTTP_TIMEOUT,
                             auth=auth_token, headers=headers,
                             verify=verify_ssl)

    if response.status_code == 200:
        logging.info(LOG_PREFIX + " Successfully executed at Icinga.")
        logging.debug(LOG_PREFIX + " Icinga response: " + str(response.content))
    else:
        logging.warning(LOG_PREFIX + " Could not execute at Icinga. Icinga Response: " + str(response.content))


def send_acknowledge_request(content_map):
    source = queue_message["source"]
    if source and source["name"].lower().startswith("icinga"):
        logging.warning("OpsGenie alert is already acknowledged by icinga. Discarding!!!")
    else:
        url_path = "/v1/actions/acknowledge-problem"
        content_map["comment"] = "Acknowledged by " + alert["username"] + " via OpsGenie"
        content_map["author"] = alert["username"]
        content_map["notify"] = True
        content_map["sticky"] = True

        expire_acknowledgement_after = args["expire_acknowledgement_after"]
        if expire_acknowledgement_after:
            expire_acknowledgement_after_seconds = int(expire_acknowledgement_after) * 60
            second = int(round(time.time()))
            timestamp = expire_acknowledgement_after_seconds + second
            content_map["expiry"] = timestamp

        post_to_icingaApi(url_path, content_map)

def send_unacknowledge_request(content_map):
    url_path = "/v1/actions/remove-acknowledgement"
    content_map["comment"] = "UnAcknowledged by " + alert["username"] + " via OpsGenie"
    content_map["author"] = alert["username"]
    content_map["notify"] = True
    post_to_icingaApi(url_path, content_map)

def send_take_ownership_request(content_map):
    url_path = "/v1/actions/add-comment"
    content_map["comment"] = "alert ownership taken by " + alert["username"]
    content_map["author"] = "OpsGenie"
    post_to_icingaApi(url_path, content_map)


def send_assign_ownership_request(content_map):
    url_path = "/v1/actions/add-comment"
    content_map["comment"] = "alert ownership assigned to " + alert["owner"]
    content_map["author"] = "OpsGenie"
    post_to_icingaApi(url_path, content_map)


def send_add_note_request(content_map):
    url_path = "/v1/actions/add-comment"
    content_map["comment"] = alert["note"] + " by " + alert["username"]
    content_map["author"] = "OpsGenie"
    post_to_icingaApi(url_path, content_map)


def attach(is_service_alert):
    perf_data = get_perf_data(is_service_alert)
    html_text = create_html(is_service_alert, perf_data)
    logging.info("Attaching details")

    file_date = time.strftime("%Y_%m_%d_%H_%m_%s")
    file_name = os.path.join(DIR_PATH, "details_{}.zip".format(file_date))

    zip_file = zipfile.ZipFile(file_name, 'w')
    zip_file.writestr('index.html', html_text)
    if perf_data:
        zip_file.writestr('perfData.png', perf_data)
    zip_file.close()

    zip_obj = open(file_name, 'rb')
    attach_alert_url = args['opsgenieUrl'] + "/v2/alerts/" + alert_from_opsgenie[
        "id"] + "/attachments?alertIdentifierType=id"

    headers = {
        "Authorization": "GenieKey " + args['apiKey']
    }

    response = requests.post(attach_alert_url, None, headers=headers, files={"file": (file_name, zip_obj)},
                             timeout=HTTP_TIMEOUT)

    if 200 <= response.status_code < 400:
        logging.info("Successfully attached details " + file_name)
    else:
        logging.info("Could not attach details " + file_name + ". Response: " + str(response.content))


def create_html(is_service_alert, perf_data):
    buf = """"
        <html>
            <head>
                <style>
                    .well{border: 1px solid #C0C0C0; border-radius: 4px; padding: 5px;background-color:#f2f2f2}
                    .CRITICAL{background-color: #F88888;border: 1px solid #777;font-weight: bold;}
                    .OK{ background-color: #88d066; border: 1px solid #777777; font-weight: bold;}
                    .WARNING{ background-color: #ffff00; border: 1px solid #777777; font-weight: bold;}
                    .UNKNOWN{ background-color: #ffbb55; border: 1px solid #777777; font-weight: bold;}
                    .img{margin:20px 0;}
                </style>
            </head>
            <body>
                <div>
    """
    if is_service_alert:
        buf += get_service_status_html()
    else:
        buf += get_host_status_html()

    if perf_data:
        buf += """<div class="img"><img src="perf_data.png"></div>"""

    buf += """
                </div>
            </body>
        </html>
    """
    return buf


def parse_from_details(key):
    if key in alert_from_opsgenie["details"].keys():
        return alert_from_opsgenie["details"][key]
    return ""


def get_host_status_html():
    date_formatter = "%m-%d-%Y %H:%M:%S"
    host_group = parse_from_details("host_group_name")
    member_of = host_group if host_group else 'No host groups'
    state = parse_from_details("host_state")
    last_check_time = parse_from_details("last_host_check")
    last_state_change = parse_from_details("last_host_state_change")

    if last_check_time:
        last_check_time = time.strftime(date_formatter, time.localtime(int(last_check_time)))
    if last_state_change:
        last_state_change = time.strftime(date_formatter, time.localtime(int(last_state_change)))

    host_alias_ = parse_from_details("host_alias")
    details_host_name_ = parse_from_details("host_name")
    host_duration_ = parse_from_details("host_duration")
    host_output_ = parse_from_details("host_output")
    host_perf_data_ = parse_from_details("host_perf_data")
    max_host_attempts_ = parse_from_details("max_host_attempts")
    host_attempt_ = parse_from_details("host_attempt")
    state_type_ = parse_from_details("host_state_type")
    host_latency_ = parse_from_details("host_latency")
    host_address_ = parse_from_details("host_address")

    buf = """
                <div class="well">
                    <table>
                        <tbody>
                            <tr><td><b>Host:</b></td><td>""" + html.escape(
        host_alias_) + """ (""" + html.escape(
        details_host_name_) + """)</td></tr>
                            <tr><td><b>Address:</b></td><td>""" + html.escape(host_address_) + """</td></tr>
                            <tr><td><b>Member of:</b></td><td>""" + html.escape(member_of) + """</td></tr>
                            <tr><td><b>Current Status:</b></td><td><span class=""""+state+"""">""" + state + """</span> for (""" + \
          host_duration_ + """)</td></tr>
                            <tr><td><b>Status Information:</b></td><td>""" + html.escape(
        host_output_) + """</td></tr>
                            <tr><td><b>Performance Data:</b></td><td>""" + html.escape(
        host_perf_data_) + """</td></tr>
                            <tr><td><b>Current Attempt:</b></td><td>""" + host_attempt_ \
          + """/""" + max_host_attempts_ + """ (""" + \
          state_type_ + """ state)</td></tr>
                            <tr><td><b>Last Check Time:</b></td><td>""" + last_check_time + """</td></tr>
                            <tr><td><b>Check Latency:</b></td><td>""" + host_latency_ + """</td></tr>
                            <tr><td><b>Last State Change:</b></td><td>""" + last_state_change + """</td></tr>
                        </tbody>
                    </table>
                </div>
           """
    return buf


def get_service_status_html():
    date_formatter = "%m-%d-%Y %H:%M:%S"
    service_group = parse_from_details("service_group_name")
    member_of = service_group if service_group else 'No service groups'
    state = parse_from_details("service_state")
    last_service_check = parse_from_details("last_service_check")
    last_state_change = parse_from_details("last_service_state_change")
    last_service_check = "" if not last_service_check.strip() else time.strftime(date_formatter,
                                                                                 time.localtime(
                                                                                     int(last_service_check)))
    last_state_change = "" if not last_state_change.strip() else time.strftime(date_formatter,
                                                                               time.localtime(int(last_state_change)))
    service = parse_from_details("service_desc")
    host_alias = parse_from_details("host_alias")
    host_name = parse_from_details("host_name")
    host_address = parse_from_details("host_address")
    service_duration = parse_from_details("service_duration")
    service_output = parse_from_details("service_output")
    service_perf_data = parse_from_details("service_perf_data")
    service_attempt_ = parse_from_details("service_attempt")
    service_state_type_ = parse_from_details("service_state_type")
    service_latency_ = parse_from_details("service_latency")
    service_attempts_ = parse_from_details("max_service_attempts")

    buf = """
                <div class="well">
                    <table>
                        <tbody>
                            <tr><td><b>Service:</b></td><td>""" + html.escape(service) + """</td></tr>
                            <tr><td><b>Host:</b></td><td>""" + html.escape(host_alias) + """ (""" + html.escape(
        host_name) + """)</td></tr>
                            <tr><td><b>Address:</b></td><td>""" + html.escape(host_address) + """</td></tr>
                            <tr><td><b>Member of:</b></td><td>""" + html.escape(member_of) + """</td></tr>
                            <tr><td><b>Current Status:</b></td><td><span class=""" + state + """>""" + state + """</span> for (""" + \
          service_duration + """)</td></tr>
                            <tr><td><b>Status Information:</b></td><td>""" + html.escape(
        service_output) + """</td></tr>
                            <tr><td><b>Performance Data:</b></td><td>""" + html.escape(
        service_perf_data) + """</td></tr>
                            <tr><td><b>Current Attempt:</b></td><td>""" + service_attempt_ + """/""" + service_attempts_ + """ (""" + \
          service_state_type_ + """ state)</td></tr>
                            <tr><td><b>Last Check Time:</b></td><td>""" + last_service_check + """</td></tr>
                            <tr><td><b>Check Latency:</b></td><td>""" + service_latency_ + """</td></tr>
                            <tr><td><b>Last State Change:</b></td><td>""" + last_state_change + """</td></tr>
                        </tbody>
                    </table>
                </div>
           """
    return buf


def get_perf_data(is_service_alert):
    graphite_url = args["graphite_url"]
    if not graphite_url:
        logging.error("Could not get performance data because graphite_url is not configured.")
        return
    host = parse_from_details("host_name")
    if is_service_alert:
        service = parse_from_details("service_desc")
        target_param = "icinga2." + host + ".services." + service + ".*.perfdata.*.*"
    else:
        target_param = "icinga2." + host + ".host.*.perfdata.*.*"
    logging.debug("Sending to " + graphite_url + " target: " + target_param)

    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "application/json",
    }

    response = requests.get(graphite_url + "/render", headers=headers, params={"target": target_param},
                            auth=auth_token, timeout=HTTP_TIMEOUT)
    code = response.status_code
    if code == 200:
        logging.info("Image received")
        return response.content
    else:
        logging.error("Could not get image from url " + graphite_url + ". ResponseCode:" + str(code) + " Reason:" + str(
            response.content))
        return None


def main():
    global LOG_PREFIX
    global HTTP_TIMEOUT
    global alert
    global auth_token
    global alert_from_opsgenie

    action = queue_message["action"]
    alert = queue_message["alert"]

    LOG_PREFIX = '[' + action + ']'
    username = args["user"]
    password = args['password']
    HTTP_TIMEOUT = args['timeout']
    auth_token = HTTPBasicAuth(username, password)

    if not HTTP_TIMEOUT:
        HTTP_TIMEOUT = 30000
    else:
        HTTP_TIMEOUT = int(HTTP_TIMEOUT)

    logging.debug("Username: " + username)

    get_alert_url = args['opsgenieUrl'] + "/v2/alerts/" + alert["alertId"] + "?alertIdentifierType=id"

    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "application/json",
        "Authorization": "GenieKey " + args['apiKey']
    }

    response = requests.get(get_alert_url, headers=headers, timeout=HTTP_TIMEOUT)

    content = response.json()
    if "data" in content.keys():
        alert_from_opsgenie = content["data"]
        host = parse_from_details("host_name")
        service = parse_from_details("service_desc")

        content_map = {}
        is_service_alert = service.strip() != ""

        if is_service_alert:
            content_map["type"] = "Service"
            content_map["filter"] = "host.name==\"" + host + "\" && service.name==\"" + service + "\""
        else:
            content_map["type"] = "Host"
            content_map["filter"] = "host.name==\"" + host + "\""

        if action == 'Create':
            send_create_request(is_service_alert)
        elif action == "Acknowledge":
            send_acknowledge_request(content_map)
        elif action == "UnAcknowledge":
            send_unacknowledge_request(content_map)
        elif action == "TakeOwnership":
            send_take_ownership_request(content_map)
        elif action == "AssignOwnership":
            send_assign_ownership_request(content_map)
        elif action == "AddNote":
            send_add_note_request(content_map)
    else:
        logging.warning(
            LOG_PREFIX + " Alert with id " + alert["alertId"] + " does not exist in Opsgenie. It is probably deleted.")


if __name__ == '__main__':
    main()
