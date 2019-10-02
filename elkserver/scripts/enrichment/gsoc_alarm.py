#!/usr/bin/python3 

import requests

class PushoverAlarm(object):
    @classmethod
    def alert(cls, title="Enrichement Alert", message="OH NO!"):
        with open("/etc/redelk/pushover.conf", "r") as pushover_conf:
            api_key = pushover_conf.read().strip()

        with open("/etc/redelk/pushover_users.conf", "r") as pushover_users:            
            for pushover_user in pushover_users.readlines():
                token = {"token": api_key, "user": pushover_user.strip()}
                token['title'] = title
                token['message'] = message
                response = requests.request("POST", "https://api.pushover.net/1/messages.json", params=token)


if __name__ == "__main__":
    PushoverAlarm.alert()