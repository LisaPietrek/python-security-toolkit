from datetime import datetime
from pydantic.dataclassesimport dataclass
import re, sys

HEADER_PATTERN = re.compile(
                        r"^(?P<month>\w+)\s+"
                        r"(?P<day>\d+)\s+"
                        r"(?P<time>\d+:\d+:\d+)\s+"
                        r"(?P<host>\S+)\s+"
                        r"(?P<service>\w+)\[(?P<pid>\d+)\]:\s*"
                        r"(?P<message>.*)$"
                        )

# to keep it simple, we use  different patterns for the message
# also a nice excercise for pattern matching
FAILED_PASSWORD_PATTERN = re.compile(
    r"^(?P<event>Failed password) "
    r"for invalid user "
    r"(?P<username>\w+) "
    r"from "
    r"(?P<ip>\d+\.\d+\.\d+.\d+)" 
                        )



def parse_header(line: str) -> dict:
    match = HEADER_PATTERN.match(line)
    if match:
        header_d = match.groupdict()
    return header_d

def parse_message(header_d: dict) -> dict:
    full_message = header_d["message"]
    match = FAILED_PASSWORD_PATTERN.match(full_message)
    if match:
        message_d = match.groupdict()
    """TODO
    add more patterns for possible messages"""
    return message_d


if __name__ == "__main__":
    #file = sys.argv[1]
    #with open(file) as f: 
    #    line = f.readline().strip()
    # made up test case
    line = "Aug  7 09:41:12 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 51432 ssh2"
    d = parse_header(line)
    print(d)
    print(parse_message(d))
