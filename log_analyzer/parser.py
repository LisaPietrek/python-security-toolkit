from datetime import datetime
from pydantic.dataclasses import dataclass
import re, sys

@dataclass
class MessagePattern:
    event: str
    pattern: re.Pattern

@dataclass
class LogEntry:
    timestamp: datetime
    host: str
    service: str
    pid: int
    event: str
    user: str | None
    ip: str | None
    context: str | None

HEADER_PATTERN = re.compile(
                        r"^(?P<month>\w+)\s+"
                        r"(?P<day>\d+)\s+"
                        r"(?P<time>\d+:\d+:\d+)\s+"
                        r"(?P<host>\S+)\s+"
                        r"(?P<service>\w+)\[(?P<pid>\d+)\]:\s*"
                        r"(?P<message>.*)$"
                        )

# to keep it simple, we use  different patterns for the message
REVERSE_MAPPING_PATTERN = re.compile(
    r"^reverse mapping checking getaddrinfo for "
    r"(?P<hostname>\S+) "
    r"\[(?P<ip>\d+\.\d+\.\d+\.\d+)\] "
    r"failed - (?P<warning>.+)$"
)
USERAUTH_INVALID_PATTERN = re.compile(
    r"^input_userauth_request: invalid user "
    r"(?P<username>\S+) "
    r"\[(?P<context>\w+)\]$"
)

INVALID_USER_PATTERN = re.compile(
    r"^Invalid user "
    r"(?P<username>\S+) "
    r"from (?P<ip>\d+\.\d+\.\d+\.\d+)$"
)


AUTH_FAILURE_PATTERN = re.compile(
    r"^pam_unix\(sshd:auth\): authentication failure;.*"
    r"rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)"
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

AUTH_USER_UNKNOWN_PATTERN = re.compile(
    r"^pam_unix\(sshd:auth\): check pass; user unknown$"
)

MESSAGE_PATTERNS = {
    "reverse_mapping_failed": REVERSE_MAPPING_PATTERN,
    "invalid_user": INVALID_USER_PATTERN,
    "invalid_user_authentication": USERAUTH_INVALID_PATTERN,
    "authentication_failure": AUTH_FAILURE_PATTERN,
    "unknown_user": AUTH_USER_UNKNOWN_PATTERN,
    "failed_login": FAILED_PASSWORD_PATTERN,
    "connection_closed": CONNECTION_CLOSED_PATTERN,
}


MESSAGE_PATTERNS = [
    MessagePattern(
        event="failed_authentication",
        pattern=FAILED_PASSWORD_PATTERN
    ),
    MessagePattern(
        event="failed_authentication",
        pattern=AUTH_FAILURE_PATTERN
    ),
    MessagePattern(
        event="invalid_user",
        pattern=INVALID_USER_PATTERN
    ),
    MessagePattern(
        event="invalid_user",
        pattern=USERAUTH_INVALID_PATTERN
    ),
    MessagePattern(
        event="unknown_user",
        pattern=AUTH_USER_UNKNOWN_PATTERN
    ),
    MessagePattern(
        event="connection_closed",
        pattern=CONNECTION_CLOSED_PATTERN
    ),
    MessagePattern( 
        event="suspicious_connection",
        pattern=REVERSE_MAPPING_PATTERN
    )
]


def parse_header(line: str) -> dict:
    match = HEADER_PATTERN.match(line)
    if match:   
       return match.groupdict()

def parse_message(message: str) -> dict:
    for entry in MESSAGE_PATTERNS:
        match = entry.pattern.match(message)

        if match:
            return {
                "event": entry.event, **match.groupdict()
            }
    return None

if __name__ == "__main__":
    file = sys.argv[1]
    with open(file) as f: 
        for i, line in enumerate(f):
            if i >19 :
                break
            
            d = parse_header(line.strip())
            m = parse_message(d["message"])
            log_entry = LogEntry(
                        host=d["host"],
                        event=m["event"])
            """TODO:
            - continue filling log entry 
            - consider NoneType in case pattern does not match line"""
            print(log_entry)
