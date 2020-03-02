import argparse
import json
import logging
import sys

import slixmpp

parser = argparse.ArgumentParser()
parser.add_argument('-payload', '--queuePayload', help='Payload from queue', required=True)
parser.add_argument('-apiKey', '--apiKey', help='The apiKey of the integration', required=True)
parser.add_argument('-opsgenieUrl', '--opsgenieUrl', help='The url', required=True)
parser.add_argument('-logLevel', '--logLevel', help='Level of log', required=True)

parser.add_argument("-jid", "--jid", dest="jid", help="JID to use")
parser.add_argument("-password", "--password", dest="password", help="Password to use")
parser.add_argument("-room", "--room", dest="room", help="MUC room to join")

args = vars(parser.parse_args())

queue_message_string = args.get('queuePayload')
queue_message = json.loads(queue_message_string)

logging.basicConfig(stream=sys.stdout, level=args.get('logLevel'))

alert = queue_message.get("alert")
alert_id = alert.get("alertId")
action = queue_message.get("action")

LOG_PREFIX = "[" + action + "]"
CONNECTION = "connection"
TIMEOUT = 3


def create_message():
    message = ""
    alert_message = str(alert.get("message"))
    alert_username = str(alert.get("username"))
    alert_note = str(alert.get("note"))
    if alert_id:
        if action == "Create":
            message = "New alert: \"" + alert_message + "\""
        elif action == "Acknowledge":
            message = alert_username + " acknowledged alert: \"" + alert_message + "\""
        elif action == "AddNote":
            message = alert_username + " added note \"" + alert_note + "\" to the alert: \"" + alert_message + "\""
        elif action == "Close":
            message = alert_username + " closed alert: \"" + alert_message + "\""
        else:
            message = alert_username + " executed [" + action + "] action on alert: \"" + alert_message + "\""
        logging.info(LOG_PREFIX + "Will execute " + action + " for alertId " + alert_id)
    return message


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


class MUCBot(slixmpp.ClientXMPP):
    def __init__(self, jid, password, room, nick):
        slixmpp.ClientXMPP.__init__(self, jid, password)
        self.room = room
        self.nick = nick
        self.add_event_handler("session_start", self.start)

    def start(self, event):
        self.get_roster()

        self.send_presence()
        self.plugin['xep_0045'].join_muc(self.room,
                                         self.nick,
                                         wait=True)

        message = create_message()
        self.send_message(mto=self.room, mbody=message, mtype='groupchat')
        self.disconnect(wait=True)


def parse_field(key, mandatory):
    variable = queue_message.get(key)
    if variable is None or not variable.strip():
        variable = args.get(key)
    if mandatory and not variable:
        err_message = LOG_PREFIX + " Skipping action, Mandatory conf item " + key + \
                  " is missing. Check your configuration file."
        logging.error(err_message)
        raise ValueError(err_message)
    return variable


def main():
    global TIMEOUT
    logging.info("Will execute " + action + " for alertId " + alert_id)

    jid = parse_field('jid', True)
    password = parse_field('password', True)
    room = parse_field('room', True)

    xmpp = MUCBot(jid, password, room, 'Opsgenie')
    xmpp.register_plugin('xep_0045')
    xmpp.connect()
    xmpp.process(timeout=TIMEOUT)


if __name__ == '__main__':
    main()