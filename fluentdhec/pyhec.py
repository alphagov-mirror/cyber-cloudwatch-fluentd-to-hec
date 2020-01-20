import requests
import os
from typing import Tuple, Union


def send(
    token: str, host: str, payload: str, port: str = "443"
) -> Tuple[Union[int, bool], Union[str, bool]]:
    """
    Sends a request to a Splunk HEC.
    """
    uri = f"https://{host}:{port}/services/collector"
    headers = {"Authorization": f"Splunk {token}"}
    timeout = int(os.getenv("SPLUNK_HEC_TIMEOUT", "10"))
    try:
        r = requests.post(uri, payload, headers=headers, verify=True, timeout=timeout,)
        return (
            r.status_code,
            r.text,
        )
    except requests.exceptions.Timeout:
        print(f"ERROR: PyHEC:send: Exceeded timeout: {timeout}")
        return False, False
