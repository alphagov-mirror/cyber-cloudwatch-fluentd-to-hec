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
    res = False
    regex = r'[A-Z]+\s\[(?P<timestamp>[^]]+)|usecs:(?P<usec>[0-9]+)'
    match = re.search(regex, message)
    if match:
        for poss_matches in ["timestamp", "usec"]:
            if match.groupdict()[poss_matches] is not None:
                res = match.groupdict()[poss_matches]
                break

        if not res.isdigit():
            try:
                dtmp = dateparser.parse(res)
                res = int(dtmp.timestamp())
            except Exception as e:
                print(f'fluentdhec.lambda_handler:extract_time: error: {e}')
        else:
            res = int(res)
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
