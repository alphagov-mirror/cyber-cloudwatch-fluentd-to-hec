import json
import re


def jsoniser(message):
    regex = re.compile(r'Time:\s(?P<timestamp>[^,]+)[\s\S]*?:\s(?P<sequence_number>\S+)[\s\S]*?:\s(?P<reboot_counter>[^$\n]+)[\s\S]*?:\s(?P<command_type>[^$\n]+)[\s\S]*?:\s(?P<opcode>[^$\n]+)[\s\S]*?:\s(?P<session_handle>[^$\n]+)[\s\S]*?:\s(?P<response>[^$\n]+)[\s\S]*?:\s(?P<log_type>[^$\n]+)[\s\S]*?(?P<log_details>[^+]+)', re.MULTILINE)
    return json.dumps((re.match(regex, message)).groupdict())
