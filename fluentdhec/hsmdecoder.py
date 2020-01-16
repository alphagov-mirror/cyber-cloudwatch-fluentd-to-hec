import json
import re


def jsoniser(message: str) -> str:
    regexs = [
        r'Time\s*: (?P<timestamp>[^,]*),',
        r'Sequence No\s+: (?P<sequence_number>.*)',
        r'Reboot counter\s+: (?P<reboot_counter>.*)',
        r'Command Type\(hex\)\s+: (?P<command_type>.*)',
        r'Opcode\s+: (?P<opcode>.*)',
        r'Session Handle\s+: (?P<session_handle>.*)',
        r'Response\s+: (?P<response>.*)',
        r'Log type\s+: (?P<log_type>.*)',
        r'User Name\s+: (?P<username>.*)',
        r'User Type\s+: (?P<usertype>.*)',
        r'Priv/Secret Key Handle\s+: (?P<private_key_handle>.*)',
        r'Public Key Handle\s+: (?P<public_key_handle>.*)'
    ]
    d = {}
    for regex in regexs:
        match = re.search(regex, message)
        if match:
            d.update(match.groupdict())
    return json.dumps(d)
