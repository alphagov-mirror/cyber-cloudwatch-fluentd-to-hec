import os
import gzip
import json
import base64
from pyhec import PyHEC

"""
This lambda function requires two variables to be set:
 - host - http-inputs-gds.splunkcloud.com
 - token - Generate from: https://gds.splunkcloud.com/en-GB/manager/search/http-eventcollector
 
This takes kubernetes fluentd log events from cloudwatch logs and 
sends them to the splunk HEC
"""

def lambda_handler(event, context):
    b64encoded_data = event['awslogs']['data']
    compressed_data = base64.b64decode(b64encoded_data)
    uncompressed_data = gzip.decompress(compressed_data)
    data = json.loads(uncompressed_data)
    log_events = data['logEvents']
    payload = build_payload(log_events, context)
    send_to_hec(payload)
    
def build_payload(log_events, context):
    payload = ""
    for log in log_events:
        log = json.loads(log['message'])
        event = {
                    "host": context.invoked_function_arn.split(':')[4],
                    "source": context.log_group_name.split('/')[-1],
                    "sourcetype": log['kubernetes']['container_name'],
                    "index": "verify_notifications_test",
                    "event": log['log']
                }
        payload += json.dumps(event)
    return payload
    
def send_to_hec(payload):
    hec = PyHEC(os.environ['token'], os.environ['host'])
    hec.send(payload)


