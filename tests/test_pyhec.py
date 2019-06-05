import os
import inspect
import sys

currentdir = os.path.dirname(os.path.abspath(
    inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0, parentdir)
import fluentdhec.pyhec  # noqa


def test_pyhec():
    test = fluentdhec.pyhec.PyHEC("a", "b")
    assert test.token == "a" and \
        test.uri == "https://b:443/services/collector"


def test_pyhec():
    negative_test = False
    try:
        # random port, to trigger a connection refused
        PyHEC = fluentdhec.pyhec.PyHEC("invalid", "localhost", 24059)
        resp = PyHEC.send("blank")
    except Exception as e:
        if "Connection refused" in str(e):
            negative_test = True
        else:
            raise e
    assert negative_test
