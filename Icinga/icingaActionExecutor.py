import argparse
import html
import json
import logging
import sys
import time
import urllib.parse
import zipfile

import requests
from requests.auth import HTTPBasicAuth

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Level of log', required=True)
parser.add_argument('-command_url', '--command_url', help='Icinga Server URL', required=False)
parser.add_argument('-trends_image_url', '--trends_image_url', help='Trends URL', required=False)
parser.add_argument('-alert_histogram_image_url', '--alert_histogram_image_url', help='Alert Histogram Image URL',
                    required=False)
parser.add_argument('-user', '--user', help='User', required=True)
parser.add_argument('-password', '--password', help='Password', required=True)
parser.add_argument('-timeout', '--timeout', help='HTTP Timeout', required=False)
parser.add_argument('-scheme', '--scheme', help='Icinga scheme', required=False)
parser.add_argument('-expire_acknowledgement_after', '-expire_acknowledgement_after',
                    help='Removes acknowledgement after given value (in minutes.)', required=False)

args = vars(parser.parse_args())

queue_message_string = args['queuePayload']
queue_message = json.loads(queue_message_string)

logging.basicConfig(stream=sys.stdout, level=args['logLevel'])


def parse_field(key, mandatory):
    variable = queue_message[key]
    if not variable.strip():
        variable = args[key]
    if mandatory and not variable:
        raise ValueError(LOG_PREFIX + " Skipping action, Mandatory conf item '" + key +
                         "' is missing. Check your configuration file.")


def get_url(conf_property, backward_compatability_url):
    url = args[conf_property]
    if url:
        return url
    else:
        scheme = args["scheme"]
        if not scheme:
            scheme = "http"

        port = args["port"]
        host = args["host"]

        if not port or not host:
            logging.error(
                LOG_PREFIX +
                " Skipping action, Mandatory conf item host or port is missing. Check your configuration file.")
            raise ValueError(
                LOG_PREFIX +
                " Skipping action, Mandatory conf item host or port is missing. Check your configuration file.")

        url = urllib.parse.urlunparse(
            (scheme, host + ':' + port, urllib.parse.quote(backward_compatability_url), None, None, None))
        return url


def get_alert_histogram():
    url = get_url("alert_histogram_image_url", "/icinga/cgi-bin/histogram.cgi")
    return get_image(url)


def get_trends():
    url = get_url("trends_image_url", "/icinga/cgi-bin/trends.cgi")
    return get_image(url)


def get_image(url):
    service = parse_from_details("service_desc")
    host = parse_from_details("host_name")

    url += "?createimage&host=" + urllib.parse.urlencode(host)
    if service:
        service = alert_from_opsgenie["details"]["service_desc"]
        url += "&service=" + urllib.parse.urlencode(service)

    logging.warning("Sending request to url:" + url)
    headers = {
        "Content-Type": "application/json",
        "Accept-Language": "application/json"
    }
    response = requests.get(url, headers=headers, timeout=HTTP_TIMEOUT, auth=auth_token)
    code = response.status_code
    if code == 200:
        logging.warning("Image received")
        print("Image received")
        return response.content
    else:
        content = str(response.content)
        logging.warning("Could not get image from url " + url + ". ResponseCode:" + str(code) + " Reason:" + content)
        print("Could not get image from url " + url + ". ResponseCode:" + str(code) + " Reason:" + content)
        return None


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


def create_html(alertHistogram, trends):
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

    if "service_desc" in alert_from_opsgenie["details"].keys():
        buf = buf + get_service_status_html()
    else:
        buf = buf + get_host_status_html()

    if trends:
        buf = buf + '<div class="img"><img src="trends.png"></div>'

    if alertHistogram:
        buf = buf + '<div class="img"><img src="alertHistogram.png"></div>'

    buf = buf + """
                    </div>
                </body>
            </html>
        """
    return buf


def attach():
    alert_histogram = get_alert_histogram()
    trends = get_trends()

    html_text = create_html(alert_histogram, trends)

    file_date = time.strftime("%Y_%m_%d_%H_%m_%s")
    file_name = "details_" + file_date + ".zip"

    zip = zipfile.ZipFile(file_name, 'w')
    zip.writestr('index.html', html_text)
    if alert_histogram:
        zip.writestr('alert_histogram.png', alert_histogram)
    if trends:
        zip.writestr('trends.png', trends)

    zip.close()

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


def send_create_request():
    attach()


def post_to_icinga_api(post_params):
    url = get_url("command_url", "/icinga/cgi-bin/cmd.cgi")
    logging.debug(LOG_PREFIX + "Posting to Icinga. Url " + url + " params:" + str(post_params))
    response = requests.post(url, post_params, timeout=HTTP_TIMEOUT, auth=auth_token)

    if 200 <= response.status_code < 400:
        logging.info(LOG_PREFIX + " Successfully executed at Icinga.")
        logging.debug(
            LOG_PREFIX + " Icinga response: " + str(response.content) + " response code: " + str(response.status_code))
    else:
        logging.warning(LOG_PREFIX + " Could not execute at Icinga. Icinga status code: " + str(
            response.status_code) + "response: " + str(response.content))


def send_acknowledge_request(post_params, service):
    source = queue_message["source"]
    if source and source["name"].lower().startswith("icinga"):
        logging.warning("OpsGenie alert is already acknowledged by icinga. Discarding!!!")
    else:
        post_params['com_data'] = "Acknowledged by " + alert["username"] + " via OpsGenie"
        post_params['sticky_ack'] = "on"
        if service:
            post_params["cmd_typ"] = "34"
        else:
            post_params["cmd_typ"] = "33"

        post_to_icinga_api(post_params)


def send_unacknowledge_request(post_params, service):
    source = queue_message["source"]
    if source and source["name"].lower().startswith("icinga"):
        logging.warning("OpsGenie alert is already acknowledged by icinga. Discarding!!!")
    else:
        if service:
            post_params["cmd_typ"] = "52"
        else:
            post_params["cmd_typ"] = "51"

        post_to_icinga_api(post_params)


def send_take_ownership_request(post_params, service):
    post_params['com_data'] = "alert ownership taken by " + alert["username"]
    if service:
        post_params["cmd_typ"] = "3"
    else:
        post_params["cmd_typ"] = "1"
    post_to_icinga_api(post_params)


def send_assign_ownership_request(post_params, service):
    post_params['com_data'] = "alert ownership assigned to " + alert["owner"]
    if service:
        post_params["cmd_typ"] = "3"
    else:
        post_params["cmd_typ"] = "1"
    post_to_icinga_api(post_params)


def send_add_note_request(post_params, service):
    post_params['com_data'] = alert["note"] + " by " + alert["username"]
    if service:
        post_params["cmd_typ"] = "3"
    else:
        post_params["cmd_typ"] = "1"
    post_to_icinga_api(post_params)


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

    response = requests.get(get_alert_url, None, headers=headers, timeout=HTTP_TIMEOUT)

    content = response.json()
    print(content)
    if "data" in content.keys():
        alert_from_opsgenie = content["data"]
        host = parse_from_details("host_name")
        service = parse_from_details("service_desc")

        postParams = {"btnSubmit": "Commit", "cmd_mod": "2", "send_notification": "off", "host": host}
        if service:
            postParams["hostservice"] = host + "^" + service

        if action == 'Create':
            send_create_request()
        elif action == "Acknowledge":
            send_acknowledge_request(postParams, service)
        elif action == "UnAcknowledge":
            send_unacknowledge_request(postParams, service)
        elif action == "TakeOwnership":
            send_take_ownership_request(postParams, service)
        elif action == "AssignOwnership":
            send_assign_ownership_request(postParams, service)
        elif action == "AddNote":
            send_add_note_request(postParams, service)
    else:
        logging.warning(
            LOG_PREFIX + " Alert with id " + alert["alertId"] + " does not exist in Opsgenie. It is probably deleted.")


if __name__ == '__main__':
    main()
