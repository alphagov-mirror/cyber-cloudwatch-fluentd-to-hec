import os
import inspect
import sys
import pytest
import json
currentdir = os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir + '/fluentdhec')
import fluentdhec.lambda_function  # noqa


@pytest.fixture
def k8s_event():
    with open('tests/fixtures/cloudwatch_logs_k8s.json') as f:
        j = json.loads(f.read())
    return j


@pytest.fixture
def k8s_second_event():
    with open('tests/fixtures/cloudwatch_logs_k8s_second.json') as f:
        j = json.loads(f.read())
    return j


@pytest.fixture
def k8s_api_event():
    with open('tests/fixtures/cloudwatch_logs_k8s_api.json') as f:
        j = json.loads(f.read())
    return j


@pytest.fixture
def hsm_event():
    with open('tests/fixtures/cloudwatch_logs_hsm.json') as f:
        j = json.loads(f.read())
    return j


@pytest.fixture
def vpc_event():
    with open('tests/fixtures/cloudwatch_logs_vpc.json') as f:
        j = json.loads(f.read())
    return j


class Oo():
    pass


@pytest.fixture
def context():
    o = Oo()
    o.function_name = 'function_name'
    return o


def test_invalid_extract_time():
    message = "syslog nope temp"
    resp = fluentdhec.lambda_function.extract_time(message)
    assert not resp


def test_syslog_1_extract_time():
    message = "syslog INFO [20/05/2019 16:01:30.123] temp"
    resp = fluentdhec.lambda_function.extract_time(message)
    assert resp == 1558364490


def test_syslog_1_extract_time_with_comma():
    message = "syslog INFO [20/05/2019 16:01:30,456] temp"
    resp = fluentdhec.lambda_function.extract_time(message)
    assert resp == 1558364490


def test_syslog_2_extract_time():
    message = "syslog INFO [2019 May 20 04:01:30 PM] temp"
    resp = fluentdhec.lambda_function.extract_time(message)
    assert resp == 1558364490


def test_syslog_3_extract_time():
    message = "syslog INFO 1997-07-16T19:20+01:00 temp"
    resp = fluentdhec.lambda_function.extract_time(message)
    assert resp == 869077200


def test_syslog_4_extract_time():
    message = "syslog INFO [2019/May/20:04:01:30 PM] temp"
    resp = fluentdhec.lambda_function.extract_time(message)
    assert resp == 1558364490


def test_syslog_5_extract_time():
    # should only match the first time
    message = "syslog 2019 May 20 04:01:30 PM test 1997-07-16T19:20+01:00"
    resp = fluentdhec.lambda_function.extract_time(message)
    assert resp == 1558364490


def test_usec_1_extract_time():
    message = "blah usecs:1558360830.123 test usec:12345 end"
    resp = fluentdhec.lambda_function.extract_time(message)
    assert resp == 1558360830


def test_usec_2_extract_time():
    message = "blah usecs:1558360830 end"
    resp = fluentdhec.lambda_function.extract_time(message)
    assert resp == 1558360830


def test_lf_send_payload_k8s(k8s_event, context, mocker):
    mocker.patch.dict(os.environ, {"SPLUNK_INDEX": "k8s"})
    mocker.patch('fluentdhec.lambda_function.send_to_hec')

    fluentdhec.lambda_function.lambda_handler(k8s_event, context)
    assert fluentdhec.lambda_function.send_to_hec.call_count == 1


def test_lf_send_payload_k8s_second(k8s_second_event, context, mocker):
    mocker.patch.dict(os.environ, {"SPLUNK_INDEX": "k8s"})
    mocker.patch('fluentdhec.lambda_function.send_to_hec')

    # all the `cloudwatch_logs_k8s_second.json` events are healthchecks
    fluentdhec.lambda_function.lambda_handler(k8s_second_event, context)
    assert fluentdhec.lambda_function.send_to_hec.call_count == 0


def test_lf_send_payload_k8s_api(k8s_api_event, context, mocker):
    mocker.patch.dict(os.environ, {"SPLUNK_INDEX": "k8s"})
    mocker.patch('fluentdhec.lambda_function.send_to_hec')

    fluentdhec.lambda_function.lambda_handler(k8s_api_event, context)
    called_args = fluentdhec.lambda_function.send_to_hec.call_args

    assert fluentdhec.lambda_function.send_to_hec.call_count == 1 and \
        "generic:k8s" in called_args[0][0]


def test_lf_send_payload_hsm(hsm_event, context, mocker):
    mocker.patch.dict(os.environ, {"SPLUNK_INDEX": "hsm"})
    mocker.patch('fluentdhec.lambda_function.send_to_hec')

    fluentdhec.lambda_function.lambda_handler(hsm_event, context)

    assert fluentdhec.lambda_function.send_to_hec.call_count == 1


def test_lf_send_payload_vpc(vpc_event, context, mocker):
    mocker.patch.dict(os.environ, {"SPLUNK_INDEX": "vpc"})
    mocker.patch('fluentdhec.lambda_function.send_to_hec')

    fluentdhec.lambda_function.lambda_handler(vpc_event, context)

    assert fluentdhec.lambda_function.send_to_hec.call_count == 1
