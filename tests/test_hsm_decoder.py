import pytest
import json
import sys
import os
import inspect

currentdir = os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)
from fluentdhec.hsmdecoder import jsoniser  # noqa


@pytest.fixture(scope='module')
def hsm_login_error():
    with open("tests/fixtures/hsm_login_error_user_doesnt_exist", "r") as f:
        hsm_test_event = f.read()
    return json.loads(jsoniser(hsm_test_event))


@pytest.fixture(scope='module')
def hsm_wrap_key():
    with open("tests/fixtures/hsm_wrap_key", "r") as f:
        hsm_test_event = f.read()
    return json.loads(jsoniser(hsm_test_event))


def test_jsonizer_can_extract_timestamp(hsm_login_error):
    assert hsm_login_error['timestamp'] == '02/18/19 12:13:50.326973'


def test_jsonizer_can_extract_sequence_number(hsm_login_error):
    assert hsm_login_error['sequence_number'] == '0xd'


def test_jsonizer_can_extract_reboot_counter(hsm_login_error):
    assert hsm_login_error['reboot_counter'] == '0xd'


def test_jsonizer_can_extract_command_type(hsm_login_error):
    assert hsm_login_error['command_type'] == 'CN_MGMT_CMD (0x0)'


def test_jsonizer_can_extract_op_code(hsm_login_error):
    assert hsm_login_error['opcode'] == 'CN_LOGIN (0xd)'


def test_jsonizer_can_extract_session_handle(hsm_login_error):
    assert hsm_login_error['session_handle'] == '0x2010005'


def test_jsonizer_can_extract_response(hsm_login_error):
    assert hsm_login_error['response'] == (
        "206:HSM Error: This user doesn't exist"
    )


def test_jsonizer_can_extract_username(hsm_login_error):
    assert hsm_login_error['username'] == 'ahahah'


def test_jsonizer_can_extract_usertype(hsm_login_error):
    assert hsm_login_error['usertype'] == 'CN_CRYPTO_USER (1)'


def test_jsonizer_can_extract_private_key_handle(hsm_wrap_key):
    assert hsm_wrap_key['private_key_handle'] == '6'


def test_jsonizer_can_extract_public_key_handle(hsm_wrap_key):
    assert hsm_wrap_key['public_key_handle'] == '0'


def test_jsonizer_can_extract_public_key_handle(hsm_wrap_key):
    print(hsm_wrap_key)
    assert hsm_wrap_key['key_handle'] == '131477'
