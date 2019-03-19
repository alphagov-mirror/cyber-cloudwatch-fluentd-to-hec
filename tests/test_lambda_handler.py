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
def hsm_event():
    with open('tests/fixtures/cloudwatch_logs_hsm.json') as f:
        j = json.loads(f.read())
    return j


class Oo():
    pass


@pytest.fixture
def context():
    o = Oo()
    o.function_name = 'function_name'
    return o


def test_lf_send_payload_k8s(k8s_event, context, mocker):
    mocker.patch.dict(os.environ, {"SPLUNK_INDEX": "k8s"})
    mocker.patch('fluentdhec.lambda_function.send_to_hec')

    fluentdhec.lambda_function.lambda_handler(k8s_event, context)
    assert fluentdhec.lambda_function.send_to_hec.call_count == 1


def test_lf_send_payload_hsm(hsm_event, context, mocker):
    mocker.patch.dict(os.environ, {"SPLUNK_INDEX": "hsm"})
    mocker.patch('fluentdhec.lambda_function.send_to_hec')

    fluentdhec.lambda_function.lambda_handler(hsm_event, context)

    assert fluentdhec.lambda_function.send_to_hec.call_count == 1
