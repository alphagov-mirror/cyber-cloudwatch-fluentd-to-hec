#!/usr/bin/env python3
import pytest
import json
import re
import sys
sys.path.append('..')
import hsmdecoder
with open("hsm_test_event", "r") as f:
    hsm_test_event = f.read()

@pytest.fixture(scope='module')

def jsonized_test_data():
    jsonized_data = json.loads(hsmdecoder.jsoniser(hsm_test_event))
    return jsonized_data

def test_jsonizer_can_extract_timestamp(jsonized_test_data):
    assert jsonized_test_data['timestamp'] == '02/18/19 12:13:50.326973'

def test_jsonizer_can_extract_sequence_number(jsonized_test_data):
    assert jsonized_test_data['sequence_number'] == '0xd'

def test_jsonizer_can_extract_reboot_counter(jsonized_test_data):
    assert jsonized_test_data['reboot_counter'] == '0xd'

def test_jsonizer_can_extract_command_type(jsonized_test_data):
    assert jsonized_test_data['command_type'] == 'CN_MGMT_CMD (0x0)'

def test_jsonizer_can_extract_op_code(jsonized_test_data):
    assert jsonized_test_data['opcode'] == 'CN_LOGIN (0xd)'

def test_jsonizer_can_extract_session_handle(jsonized_test_data):
    assert jsonized_test_data['session_handle'] == '0x2010005'

def test_jsonizer_can_extract_response(jsonized_test_data):
    assert jsonized_test_data['response'] == "206:HSM Error: This user doesn't exist"

def test_jsonizer_can_extract_log_type(jsonized_test_data):
    assert jsonized_test_data['log_details'] == '\nUser Name\t\t: ahahah\nUser Type\t\t: CN_CRYPTO_USER (1)\n'
