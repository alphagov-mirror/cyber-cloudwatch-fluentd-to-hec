import requests


class HEC:
    def __init__(self, token, host, port='443'):
        self.token = token
        self.uri = f"https://{host}:{port}/services/collector"

    def send(self, payload):
        headers = {'Authorization': f"Splunk {token}"}
        r = requests.post(self.uri, payload, headers=headers, verify=True)
        return r.status_code, r.text,
