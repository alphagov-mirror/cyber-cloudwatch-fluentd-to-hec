import os
import gzip
import json
import base64
import re
import dateparser
from pyhec import PyHEC
from datetime import datetime
import hsmdecoder

"""
This lambda function requires three variables to be set:
 - SPLUNK_HEC_URL - http-inputs-gds.splunkcloud.com
 - SPLUNK_HEC_TOKEN - Generate from:
   https://gds.splunkcloud.com/en-GB/manager/search/http-eventcollector
 - SPLUNK_INDEX - Name of the index agreed upon

This takes kubernetes fluentd and HSM audit log events from cloudwatch
logs and sends them to the splunk HEC
"""


def lambda_handler(event, context):
    b64encoded_data = event['awslogs']['data']
    compressed_data = base64.b64decode(b64encoded_data)
    uncompressed_data = gzip.decompress(compressed_data)
    data = json.loads(uncompressed_data)

    payload = None
    if 'k8s' in os.environ['SPLUNK_INDEX']:
        payload = build_payload_k8s(data)
    if 'hsm' in os.environ['SPLUNK_INDEX']:
        payload = build_payload_hsm(data, context)
    if payload:
        send_to_hec(payload)


def extract_time(message):
    # this matches date and 2 / 4 digit year values (19 vs 2019)
    # rDOrY could be either at start or end (2019 MM DD or DD MM 2019)
    rDOrY = r"\d{2,4}"
    # rMonth could be character (May) or 2 digit (05)
    rMonth = r"(?:[a-zA-Z]+|\d\d)"
    # for optional timezones
    rTimeZone = r"[\+-]\d\d\:?\d\d"
    # rTime matches timestamps with optional seconds and optional timezones
    rTime = rf"\d\d\:\d\d(?:\:\d\d)?(?:[\.,]\d+)?(?:Z| AM| PM|{rTimeZone})?"

    regex = rf'(?P<t>{rDOrY}.{rMonth}.{rDOrY}?.{rTime})|usecs:(?P<s>[0-9]+)'
    match = re.search(regex, message)

    try:
        res = [
            int(dateparser.parse(timestamp.replace(",", ".")).timestamp())
            for timestamp in match.groupdict().values()
            if timestamp
        ][0]
    except AttributeError:
        res = False

    return res


def build_payload_k8s(data):
    payload = ""
    log_events = data['logEvents']
    cluster_name = data['logGroup']
    for log in log_events:
        jlog = json.loads(log['message'])

        event = {
            "host": jlog['kubernetes']['pod_name'],
            "source": cluster_name,
            "sourcetype": jlog['kubernetes']['container_name'],
            "index": os.environ['SPLUNK_INDEX'],
            "event": jlog['log']
        }

        time = extract_time(jlog['log'])
        if time:
            event["time"] = time

        payload += json.dumps(event)
    return payload


def build_payload_hsm(data, context):
    payload = ""
    log_events = data['logEvents']
    cluster_name = data['logGroup']
    for log in log_events:
        event = {
            "host": cluster_name,
            "source": context.function_name,
            "sourcetype": "cloudhsm",
            "index": os.environ['SPLUNK_INDEX'],
            "event": hsmdecoder.jsoniser(log['message'])
        }

        time = extract_time(log['message'])
        if time:
            event["time"] = time

        payload += json.dumps(event)
    return payload


def send_to_hec(payload):
    hec = PyHEC(os.environ['SPLUNK_HEC_TOKEN'], os.environ['SPLUNK_HEC_URL'])
    hec.send(payload)
