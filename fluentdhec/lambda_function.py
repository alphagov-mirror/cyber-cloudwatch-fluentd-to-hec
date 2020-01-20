import os
import gzip
import json
import base64
import re
from typing import Dict

import dateparser  # type: ignore

from .pyhec import PyHEC
from . import hsmdecoder

"""
This lambda function requires three variables to be set:
 - SPLUNK_HEC_URL - http-inputs-gds.splunkcloud.com
 - SPLUNK_HEC_TOKEN - Generate from:
   https://gds.splunkcloud.com/en-GB/manager/search/http-eventcollector
 - SPLUNK_INDEX - Name of the index agreed upon

This takes kubernetes fluentd and HSM audit log events from cloudwatch
logs and sends them to the splunk HEC
"""


def lambda_handler(event: Dict, context) -> None:
    """
    Sends to the HEC every event that is not a healthcheck event.
    """
    if os.getenv('EVENT_DEBUG') == '1':
        print(event)
    b64encoded_data = event['awslogs']['data']
    compressed_data = base64.b64decode(b64encoded_data)
    uncompressed_data = gzip.decompress(compressed_data)
    data = json.loads(uncompressed_data)
    for log_event in data['logEvents']:
        if is_healthcheck(log_event):
            print("INFO: build_payload_k8s: dropping healthchecks")
            continue
        event = parse_log_event(log_event)
        event["source"] = context.function_name
        event["host"] = data.get('logGroup', 'unknown')
        if "time" not in event:
            try:
                event["time"] = extract_time(log_event['message'])
            except Exception as e:
                if os.getenv('EVENT_DEBUG') == '1':
                    print(f"WARNING: ignoring {e} in extracting time value "
                          f"from {log_event['message']}")
        event_payload = json.dumps(event)
        send_to_hec(event_payload)


def is_healthcheck(log_event: Dict) -> bool:
    """
    Returns whether the log event is a healthcheck event
    Requests to `/healthcheck` and k8s probes are healthcheck events
    """
    return "/healthcheck" in log_event['message'] \
        and "kube-probe" in log_event['message']


def parse_log_event(log_event: Dict) -> Dict:
    if 'hsm' in os.environ['SPLUNK_INDEX']:
        return parse_hsm_log_event(log_event)
    return parse_k8s_log_event(log_event)


def parse_container_log_event(log_message: Dict) -> Dict:
    return {
        "host": "%s/%s" % (
           log_message['kubernetes']['namespace_name'],
           log_message['kubernetes']['pod_name']
        ),
        "sourcetype": log_message['kubernetes']['container_name'],
        "index": os.environ['SPLUNK_INDEX'],
        "event": log_message['log']
    }


def parse_k8s_log_event(log: Dict) -> Dict:
    try:
        log_message = json.loads(log['message'])
        if "kubernetes" in log_message:
            return parse_container_log_event(log_message)
        else:
            return parse_raw_event(log)
    except json.decoder.JSONDecodeError as e:
        print(f"ERROR: {e} - {log}")
        return parse_raw_event(log)


def parse_raw_event(log: Dict) -> Dict:
    return {
        "sourcetype": "generic:k8s",
        "index": os.environ['SPLUNK_INDEX'],
        "event": log['message'],
    }


def parse_hsm_log_event(log: Dict) -> Dict:
    return {
        "sourcetype": "cloudhsm",
        "index": os.environ['SPLUNK_INDEX'],
        "event": hsmdecoder.jsoniser(log['message'])
    }


def send_to_hec(payload: str) -> None:
    hec = PyHEC(os.environ['SPLUNK_HEC_TOKEN'], os.environ['SPLUNK_HEC_URL'])
    hec.send(payload)


def extract_time(message: str) -> int:
    """
    Parses a message to return a timestamp in seconds.

    >>> extract_time("usecs:12345")
    12345
    >>> extract_time("2009-Feb-13 23:31:30")
    1234567890
    """
    day_year = r"\d{2,4}"
    month = r"(?:[a-zA-Z]+|\d\d)"
    timezone = r"[\+-]\d\d\:?\d\d"
    time = rf"\d\d\:\d\d(?:\:\d\d)?(?:[\.,]\d+)? ?(?:Z|AM|PM|{timezone})?"
    time_matcher = (rf"(?P<date>{day_year}.{month}.{day_year})."
                    rf"(?P<time>{time})|usecs:(?P<timestamp>[0-9]+)")
    matches = re.search(time_matcher, message)
    if not matches:
        raise ValueError("No recognisable timestamp in message")
    if matches.group("timestamp"):
        timestamp_seconds = int(matches.group("timestamp"))
    elif matches.group("date") and matches.group("time"):
        date = matches.group("date")
        time = matches.group("time").replace(",", ".")
        datetime = dateparser.parse(f"{date} {time}")
        timestamp_seconds = int(datetime.timestamp())
    else:
        raise ValueError("No recognisable timestamp in message")
    return timestamp_seconds
