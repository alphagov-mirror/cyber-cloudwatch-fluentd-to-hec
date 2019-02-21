import json
import re


def jsoniser(message):
    regex = re.compile(r'^Time:\s(?P<timestamp>[^,]+)[\s\S]*?:\s(?P<sequence_number>\S+)\S*?$\nReboot counter\s*:(?P<reboot_counter>[^$\n]+)\S*?$\n[^:]+\S(?P<command_type>[^$\n]+)\S*?$\n[^:]+\S(?P<opcode>[^$\n]+)\S*?$\n[^:]+\S(?P<session_handle>[^$\n]+)\S*?$\n[^:]+\S(?P<response>[^$\n]+)\S*?$\n[^:]+\S(?P<log_type>[^$\n]+)\S*?$\n[^:]+\S(?P<user_name>[^$\n]+)\S*?$\n[^:]+\S(?P<user_type>[^$\n]+)', re.MULTILINE)
    return json.dumps((re.match(regex, message)).groupdict())
