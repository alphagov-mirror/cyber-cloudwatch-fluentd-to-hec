import requests
import os
from typing import Tuple, Union


class PyHEC:
    def __init__(self, token: str, host: str, port: str = '443') -> None:
        self.token = token
        self.uri = f"https://{host}:{port}/services/collector"

    def send(self, payload: str) -> Tuple[Union[int, bool], Union[str, bool]]:
        headers = {'Authorization': f'Splunk {self.token}'}
        timeout = int(os.getenv('SPLUNK_HEC_TIMEOUT', '10'))
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
