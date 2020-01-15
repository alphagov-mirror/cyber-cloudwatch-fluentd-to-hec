import os
import gzip
import json
import base64
import re
import dateparser
from pyhec import PyHEC
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
    if os.getenv('EVENT_DEBUG', '0') == '1':
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
            t = extract_time(log_event['message'])
            if type(t) is int:
                event["time"] = t
        event_payload = json.dumps(event)
        send_to_hec(event_payload)


def is_healthcheck(log_event):
    return "/healthcheck" in log_event['message'] \
        and "kube-probe" in log_event['message']


def parse_log_event(log_event):
    if 'hsm' in os.environ['SPLUNK_INDEX']:
        return parse_hsm_log_event(log_event)
    return parse_k8s_log_event(log_event)


def parse_container_log_event(jlog):
    return {
        "host": "%s/%s" % (
           jlog['kubernetes']['namespace_name'],
           jlog['kubernetes']['pod_name']
        ),
        "sourcetype": jlog['kubernetes']['container_name'],
        "index": os.environ['SPLUNK_INDEX'],
        "event": jlog['log']
    }


def parse_k8s_log_event(log):
    try:
        jlog = json.loads(log['message'])
        if "kubernetes" in jlog:
            return parse_container_log_event(jlog)
        else:
            return parse_raw_event(log)
    except json.decoder.JSONDecodeError as e:
        print('failed to parse_container_log_event:', e, log)
        return parse_raw_event(log)


def parse_raw_event(log):
    return {
        "sourcetype": "generic:k8s",
        "index": os.environ['SPLUNK_INDEX'],
        "event": log['message'],
    }


def parse_hsm_log_event(log):
    return {
        "sourcetype": "cloudhsm",
        "index": os.environ['SPLUNK_INDEX'],
        "event": hsmdecoder.jsoniser(log['message'])
    }


def send_to_hec(payload):
    hec = PyHEC(os.environ['SPLUNK_HEC_TOKEN'], os.environ['SPLUNK_HEC_URL'])
    hec.send(payload)


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
            res = int(dt.timestamp())
        except AttributeError:
            res = False
    return res
