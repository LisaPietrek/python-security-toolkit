from datetime import datetime
from pydantic.dataclasses import dataclass
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


REVERSE_MAPPING_PATTERN = re.compile(
    r"^reverse mapping checking getaddrinfo for "
    r"(?P<hostname>\S+) "
    r"\[(?P<ip>\d+\.\d+\.\d+\.\d+)\] "
    r"failed - (?P<warning>.+)$"
)

INVALID_USER_PATTERN = re.compile(
    r"^Invalid user "
    r"(?P<username>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)$"
)

USERAUTH_INVALID_PATTERN = re.compile(
    r"^input_userauth_request: invalid user "
    r"(?P<username>\S+) "
    r"\[(?P<context>\w+)\]$"
)

AUTH_FAILURE_PATTERN = re.compile(
    r"^pam_unix\(sshd:auth\): authentication failure;.*"
    r"rhost=(?P<ip>\d+\.\d+\.\d+.\d+)"
)

FAILED_PASSWORD_PATTERN = re.compile(
    r"^Failed password for "
    r"(?:invalid user )?"
    r"(?P<username>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+) "
    r"port (?P<port>\d+) "
    r"ssh2$"
)

CONNECTION_CLOSED_PATTERN = re.compile(
    r"^Connection closed by "
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)"
    r"(?: \[(?P<context>\w+)\])?$"
)

PATTERNS = {
    "failed_login": FAILED_PASSWORD_PATTERN,
    "invalid_user": INVALID_USER_PATTERN,
    "connection_closed": CONNECTION_CLOSED_PATTERN,
    "authentication_failure": AUTH_FAILURE_PATTERN,
}

"""
Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!
Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user webmaster from 173.234.31.186
Dec 10 06:55:46 LabSZ sshd[24200]: input_userauth_request: invalid user webmaster [preauth]
Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown
Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=173.234.31.186
Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2
Dec 10 06:55:48 LabSZ sshd[24200]: Connection closed by 173.234.31.186 [preauth]
Dec 10 07:02:47 LabSZ sshd[24203]: Connection closed by 212.47.254.145 [preauth]
Dec 10 07:07:38 LabSZ sshd[24206]: Invalid user test9 from 52.80.34.196
"""

def parse_header(line: str) -> dict:
    match = HEADER_PATTERN.match(line)
    if match:   
       return match.groupdict()

def parse_message(header_d: dict) -> dict:
    message = header_d["message"]
    print(message)
    """some patterns do not work as expected - 
    TODO: FIX"""
#    for event, pattern in PATTERNS.items():
#        match = pattern.match(message)
#
#        if match:
#            return event, match.groupdict()
#
#    return None
#
if __name__ == "__main__":
    file = sys.argv[1]
    with open(file) as f: 
        for i, line in enumerate(f):
            if i >9 :
                break
            
            d = parse_header(line.strip())
#            print(d)
#            print(parse_message(d))
            parse_message(d)
            
#    # made up test case
#    line = "Aug  7 09:41:12 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 51432 ssh2"
#    d = parse_header(line)
#    print(d)
#    print(parse_message(d))
