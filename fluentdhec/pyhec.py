import requests
import os


class PyHEC:
    def __init__(self, token, host, port='443'):
        self.token = token
        self.uri = f"https://{host}:{port}/services/collector"

    def send(self, payload):
        headers = {'Authorization': f'Splunk {self.token}'}
        timeout = int(s.getenv('SPLUNK_HEC_TIMEOUT', '10'))
        try:
            r = requests.post(
                self.uri,
                payload,
                headers=headers,
                verify=True,
                timeout=timeout,
            )
            return r.status_code, r.text,
        except requests.exceptions.Timeout:
            print(f"ERROR: PyHEC:send: Exceeded timeout: {timeout}")
            return False, False
