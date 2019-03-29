import os
import gzip
import json
import base64
from hec import HEC
import hsmdecoder

"""
This lambda function requires two variables to be set:
 - SPLUNK_HEC_URL - http-inputs-ORG.splunkcloud.com
 - SPLUNK_HEC_TOKEN -
 - SPLUNK_INDEX - Destination index

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


def build_payload_k8s(data):
    payload = ""
    log_events = data['logEvents']
    cluster_name = data['logGroup']
    for log in log_events:
        log = json.loads(log['message'])
        event = {
            "host": log['kubernetes']['pod_name'],
            "source": cluster_name,
            "sourcetype": log['kubernetes']['container_name'],
            "index": os.environ['SPLUNK_INDEX'],
            "event": log['log']
        }
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
        payload += json.dumps(event)
    return payload


def send_to_hec(payload):
    hec = HEC(os.environ['SPLUNK_HEC_TOKEN'], os.environ['SPLUNK_HEC_URL'])
    hec.send(payload)
