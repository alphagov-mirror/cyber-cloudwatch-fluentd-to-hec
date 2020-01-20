import requests
import os
from typing import Tuple


def send(token: str, host: str, payload: str, port: str = "443") -> Tuple[int, str]:
    """
    Sends a request to a Splunk HEC.
    """
    uri = f"https://{host}:{port}/services/collector"
    headers = {"Authorization": f"Splunk {token}"}
    timeout = int(os.getenv("SPLUNK_HEC_TIMEOUT", "10"))
    try:
        r = requests.post(uri, payload, headers=headers, verify=True, timeout=timeout,)
        return r.status_code, r.text
    except requests.exceptions.Timeout:
        print(f"ERROR: PyHEC:send: Exceeded timeout: {timeout}")
        return 408, "timeout"
