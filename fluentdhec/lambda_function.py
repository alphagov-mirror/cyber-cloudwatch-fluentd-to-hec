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
    # if 'EVENT_DEBUG' (default of '0') is '1', then print event
    if os.getenv('EVENT_DEBUG', '0') == '1':
        print(event)

    b64encoded_data = event['awslogs']['data']
    compressed_data = base64.b64decode(b64encoded_data)
    uncompressed_data = gzip.decompress(compressed_data)
    data = json.loads(uncompressed_data)

    payload = False
    if 'k8s' in os.environ['SPLUNK_INDEX']:
        build_payload_k8s(data, context)
    if 'hsm' in os.environ['SPLUNK_INDEX']:
        build_payload_hsm(data, context)
    if 'vpc' in os.environ['SPLUNK_INDEX']:
        # print(b64encoded_data)
        build_payload_vpc(data, context)


def extract_time(message):
    # this matches date and 2 / 4 digit year values (19 vs 2019)
    # rDY could be either at start or end (2019 MM DD or DD MM 2019)
    rDY = r"\d{2,4}"
    # rMon could be character (May) or 2 digit (05)
    rMon = r"(?:[a-zA-Z]+|\d\d)"
    # for optional timezones
    rTimeZone = r"[\+-]\d\d\:?\d\d"
    # rTime matches timestamps with optional seconds and optional timezones
    rTime = rf"\d\d\:\d\d(?:\:\d\d)?(?:[\.,]\d+)? ?(?:Z|AM|PM|{rTimeZone})?"

    regex = rf'(?P<d>{rDY}.{rMon}.{rDY}).(?P<t>{rTime})|usecs:(?P<s>[0-9]+)'
    # print(f"DEBUG: extract_time:regex: {regex}")
    matches = re.search(regex, message)

    res = False
    # if there are no matches, return false
    if not matches:
        return res

    # if there's a `usecs` match, use this
    if matches.group("s"):
        res = int(matches.group("s"))
    # use the date and time matches separately to make a string
    # the dateparser library is particular about certain characters
    elif matches.group("d") and matches.group("t"):
        try:
            date = matches.group("d")
            time = matches.group("t").replace(",", ".")
            dt = dateparser.parse(f"{date} {time}")
            # need an int of the timestamp (epoch)
            res = int(dt.timestamp())
        except AttributeError as e:
            print(e)
            res = False

    return res


def build_payload_k8s(data, context):
    # payload = ""
    log_events = data['logEvents']
    cluster_name = data['logGroup']
    for log in log_events:
        if "/healthcheck" in log['message'] and "kube-probe" in log['message']:
            print("INFO: build_payload_k8s: dropping healthchecks")
            continue

        jlog = json.loads(log['message'])

        if "kubernetes" in jlog:
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
                print(time)
        else:
            event = {
                "host": cluster_name,
                "source": context.function_name,
                "sourcetype": "generic:k8s",
                "index": os.environ['SPLUNK_INDEX'],
                "event": log['message']
            }

            time = extract_time(log['message'])
            if time:
                event["time"] = time

        event_payload = json.dumps(event)
        send_to_hec(event_payload)
    # return payload


def build_payload_hsm(data, context):
    # payload = ""
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

        event_payload = json.dumps(event)
        send_to_hec(event_payload)
    # return payload


def build_payload_vpc(data, context):
    # payload = ""
    log_events = data['logEvents']
    cluster_name = data['logGroup']
    for log in log_events:
        event = {
            "host": cluster_name,
            "source": context.function_name,
            "sourcetype": "aws:cloudwatchlogs:vpcflow",
            "index": os.environ['SPLUNK_INDEX'],
            "event": log['message'],
        }

        if "timestamp" in log:
            event["time"] = str(int(log['timestamp'] / 1000))

        event_payload = json.dumps(event)
        send_to_hec(event_payload)
    # return payload


def send_to_hec(payload):
    hec = PyHEC(os.environ['SPLUNK_HEC_TOKEN'], os.environ['SPLUNK_HEC_URL'])
    hec.send(payload)
