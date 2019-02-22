#!/usr/bin/env python3
import pytest
import json
import re
with open("hsm_test_event", "r") as f:
    hsm_test_event = f.read()

@pytest.fixture(scope='module')

def custom_test_data():

    regex = re.compile(r'Time:\s(?P<timestamp>[^,]+)[\s\S]*?:\s(?P<sequence_number>\S+)[\s\S]*?:\s(?P<reboot_counter>[^$\n]+)[\s\S]*?:\s(?P<command_type>[^$\n]+)[\s\S]*?:\s(?P<opcode>[^$\n]+)[\s\S]*?:\s(?P<session_handle>[^$\n]+)[\s\S]*?:\s(?P<response>[^$\n]+)[\s\S]*?:\s(?P<log_type>[^$\n]+)[\s\S]*?(?P<log_details>[^+]+)', re.MULTILINE)

    return json.dumps((re.match(regex, hsm_test_event)).groupdict())

def test_jsonizer_can_extract_timestamp(custom_test_data):
    data = json.loads(custom_test_data)
    assert data['timestamp'] == '02/18/19 12:13:50.326973'
    print('testing...')
    print(data)

def test_jsonizer_can_extract_sequence_number(custom_test_data):
    data = json.loads(custom_test_data)
    assert data['sequence_number'] == '0xd'

def test_jsonizer_can_extract_reboot_counter(custom_test_data):
    data = json.loads(custom_test_data)
    assert data['reboot_counter'] == '0xd'

def test_jsonizer_can_extract_command_type(custom_test_data):
    data = json.loads(custom_test_data)
    assert data['command_type'] == 'CN_MGMT_CMD (0x0)'
def test_jsonizer_can_extract_op_code(custom_test_data):
    data = json.loads(custom_test_data)
    assert data['opcode'] == 'CN_LOGIN (0xd)'

def test_jsonizer_can_extract_session_handle(custom_test_data):
    data = json.loads(custom_test_data)
    assert data['session_handle'] == '0x2010005'

def test_jsonizer_can_extract_response(custom_test_data):
    data = json.loads(custom_test_data)
    assert data['response'] == "206:HSM Error: This user doesn't exist"

def test_jsonizer_can_extract_log_type(custom_test_data):
    data = json.loads(custom_test_data)
    assert data['log_details'] == '\nUser Name\t\t: ahahah\nUser Type\t\t: CN_CRYPTO_USER (1)\n'
