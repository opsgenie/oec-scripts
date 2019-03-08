import argparse
import json
import sys
import urllib.parse
import html
import zipfile

import requests
from requests.auth import HTTPBasicAuth
import logging
import time

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--payload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-loglevel', '--loglevel', help='Level of log', required=True)
parser.add_argument('-alert_histogram_image_url', '--alert_histogram_image_url', help='Alert Histogram Image Url',
                    required=False)
parser.add_argument('-trends_image_url', '--trends_image_url', help='Trends Image Url',
                    required=False)
parser.add_argument('-command_url', '--command_url', help='Command Url', required=False)
parser.add_argument('-username', '--username', help='Username', required=True)
parser.add_argument('-ticket', '--ticket', help='Ticket', required=True)
parser.add_argument('-timeout', '--timeout', help='Timeout', required=False)
parser.add_argument('-scheme', '--scheme', help='Scheme', required=False)
parser.add_argument('-port', '--port', help='Port', required=False)
parser.add_argument('-host', '--host', help='Host', required=False)

args = vars(parser.parse_args())

logging.basicConfig(stream=sys.stdout, level=args['loglevel'])

queue_message_string = args['payload']
queue_message = json.loads(queue_message_string)


def parse_from_details(key):
    if key in alert_from_opsgenie["details"].keys():
        return alert_from_opsgenie["details"][key]
    return ""


def get_url(conf_property, backward_compatibility_url):
    url = args[conf_property]
    if url:
        return url
    else:
        # backward compatibility
        scheme = args["scheme"]
        if scheme:
            scheme = "http"

        port = args["port"]
        host = args["host"]

        if not port or not host:
            logging.error(
                LOG_PREFIX + " Skipping action, Mandatory conf item host or port is missing. Check your configuration file.")
            raise ValueError(
                LOG_PREFIX + " Skipping action, Mandatory conf item host or port is missing. Check your configuration file.")

        url = urllib.parse.urlunparse(
            (scheme, host + ':' + port, urllib.parse.quote(backward_compatibility_url), None, None, None))
        return url


def get_image(url, entity):
    host = parse_from_details("host_name")

    url += "?createimage&host=" + urllib.parse.quote(host)

    if entity == "service":
        service = parse_from_details("service_desc")
        url += "&service=" + urllib.parse.quote(service)

    url += "&username=" + args["username"]
    url += "&ticket=" + args["ticket"]

    logging.warning("Sending request to url: " + url)

    response = requests.get(url, None, auth=auth_token, timeout=timeout)

    if response.status_code == 200:
        logging.warning("Image received")
        print("Image received")
        return response.content
    else:
        content = response.content
        logging.warning("Could not get image from url " + url + ".ResponseCode: " + str(
            response.status_code) + "Reason: " + content)
        print("Could not get image from url " + url + ".ResponseCode: " + str(
            response.status_code) + "Reason: " + content)
        return None


def get_alert_histogram(entity):
    url = get_url("alert_histogram_image_url", "/nagiosxi/includes/components/nagioscore/ui/histogram.php")
    return get_image(url, entity)


def get_trends(entity):
    url = get_url("trends_image_url", "/nagiosxi/includes/components/nagioscore/ui/trends.php")
    return get_image(url, entity)


def get_host_status_html():
    date_formatter = "%m-%d-%Y %H:%M:%S"
    host_group = parse_from_details("host_group_name")
    member_of = host_group if host_group else 'No host groups'
    state = parse_from_details("host_state")
    last_check_time = parse_from_details("last_host_check")
    last_state_change = parse_from_details("last_host_state_change")
    last_check_time = time.strftime(date_formatter, time.localtime(last_check_time))
    last_state_change = time.strftime(date_formatter, time.localtime(last_state_change))
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
                                                                                 time.localtime(last_service_check))
    last_state_change = "" if not last_state_change.strip() else time.strftime(date_formatter,
                                                                               time.localtime(last_state_change))
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


def create_html(entity, alert_histogram, trends):
    buf = """
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

    if entity == "host":
        buf = buf + get_host_status_html()
    else:
        buf = buf + get_service_status_html()

    if trends:
        buf += '<div class="img"><img src="trends.png"></div>'
    if alert_histogram:
        buf += '<div class="img"><img src="alertHistogram.png"></div>'

    buf += """
                </div>
            </body>
        </html>
    """

    return buf


def attach(entity):
    alert_histogram = get_alert_histogram(entity)
    trends = get_trends(entity)
    html_text = create_html(entity, alert_histogram, trends)
    logging.warning("Attaching details")
    print("Attaching details")

    file_date = time.strftime("%Y_%m_%d_%H_%m_%s")
    file_name = "details_" + file_date + ".zip"

    # create zip
    zip_file = zipfile.ZipFile(file_name, 'w')
    zip_file.writestr('index.html', html_text)
    if alert_histogram:
        zip_file.writestr('alertHistogram.png', alert_histogram)
    if trends:
        zip_file.writestr('trends.png', trends)

    zip_file.close()

    zip_obj = open(file_name, 'rb')

    attach_alert_url = args['opsgenieUrl'] + "/v2/alerts/" + alert_from_opsgenie[
        "id"] + "/attachments?alertIdentifierType=id"

    headers = {
        "Authorization": "GenieKey " + args['apiKey']
    }

    response = requests.post(attach_alert_url, None, headers=headers, files={"file": (file_name, zip_obj)},
                             timeout=timeout)

    if response.status_code < 400:
        logging.info("Successfully attached details " + file_name)
        print("Successfully attached details")
    else:
        logging.info("Could not attach details " + file_name + ". Response: " + str(response.content))
        print("Could not attach details. Response: " + str(response.content))

    logging.warning(str(response.content))


def post_to_nagios(post_params):
    url = get_url("command_url", "/nagiosxi/includes/components/nagioscore/ui/cmd.php")
    post_params["username"] = args["username"]
    post_params["ticket"] = args['ticket']

    logging.debug(LOG_PREFIX + "Posting to Nagios. Url " + url + " params:" + str(post_params))
    response = requests.post(url, json.dumps(post_params), timeout=timeout, auth=auth_token)

    if response.status_code < 400:
        logging.info(LOG_PREFIX + " Successfully executed at Nagios.")
        logging.debug(
            LOG_PREFIX + " Nagios response: " + str(response.content) + " response code: " + str(response.status_code))
    else:
        logging.warning(LOG_PREFIX + " Could not execute at Nagios. Nagios status code: " + str(
            response.status_code) + "response: " + str(response.content))


def main():
    global LOG_PREFIX
    global alert_from_opsgenie
    global auth_token
    global timeout

    action = queue_message["action"]
    alert = queue_message["alert"]
    source = queue_message["source"]

    logging.debug("Action: " + str(action))

    LOG_PREFIX = "[" + action + "]:"
    logging.warning(LOG_PREFIX + " Will execute action for alertId " + alert["alertId"])

    username = args["username"]
    password = args['ticket']
    timeout = args['timeout']

    if timeout:
        timeout = 30000
    else:
        timeout = int(timeout)

    logging.debug("Username: " + username)
    logging.debug("Password: " + password)

    auth_token = HTTPBasicAuth(username, password)

    get_alert_url = args['opsgenieUrl'] + "/v2/alerts/" + alert["alertId"]

    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "application/json",
        "Authorization": "GenieKey " + args['apiKey']
    }

    response = requests.get(get_alert_url, None, headers=headers, timeout=timeout)
    content = response.json()

    if "data" in content.keys():
        alert_from_opsgenie = content["data"]
        host = parse_from_details("host_name")
        service = parse_from_details("service_desc")
        post_params = {"btnSubmit": "Commit", "cmd_mod": "2", "send_notification": "off", "host": host}
        if service:
            post_params['service'] = service

        discard_action = False

        if action == "Create":
            if service:
                attach(service)
            else:
                attach(host)
            discard_action = True
        elif action == "Acknowledge":
            if source and source["name"].lower().startswith("nagios"):
                logging.warning("Opsgenie alert is already acknowledged by nagios. Discarding!!!")
                discard_action = True
            else:
                post_params['com_data'] = "Acknowledged by " + alert["username"] + " via Opsgenie"
                post_params['sticky_ack'] = "on"
                if service:
                    post_params["cmd_typ"] = "34"
                else:
                    post_params["cmd_typ"] = "33"
        elif action == "UnAcknowledge":
            if source and source["name"].lower().startswith("nagios"):
                logging.warning("Opsgenie alert is already unacknowledged by nagios. Discarding!!!")
                discard_action = True
            else:
                if service:
                    post_params["cmd_typ"] = "52"
                else:
                    post_params["cmd_typ"] = "51"
        elif action == "TakeOwnership":
            post_params['com_data'] = "alert ownership taken by " + alert["username"]
            if service:
                post_params["cmd_typ"] = "3"
            else:
                post_params["cmd_typ"] = "1"
        elif action == "AssignOwnership":
            post_params['com_data'] = "alert ownership assigned to " + alert["username"]
            if service:
                post_params["cmd_typ"] = "3"
            else:
                post_params["cmd_typ"] = "1"
        elif action == "AddNote":
            post_params['com_data'] = alert["note"] + " by " + alert["username"]
            if service:
                post_params["cmd_typ"] = "3"
            else:
                post_params["cmd_typ"] = "1"

        if not discard_action:
            post_to_nagios(post_params)
    else:
        logging.warning(
            LOG_PREFIX + " Alert with id " + alert["alertId"] + " does not exist in Opsgenie. It is probably deleted.")


if __name__ == '__main__':
    main()
