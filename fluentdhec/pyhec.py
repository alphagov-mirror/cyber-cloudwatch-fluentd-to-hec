import requests


class PyHEC:
    def __init__(self, token, host, port='443'):
        self.token = token
        self.uri = "https://" + host + ":" + port + "/services/collector"

    def send(self, payload):
        headers = {'Authorization': 'Splunk ' + self.token}
        r = requests.post(self.uri, payload, headers=headers, verify=True)
        return r.status_code, r.text,
