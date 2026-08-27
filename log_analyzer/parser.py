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
    user: str | None = None
    ip: str | None = None
    context: str | None = None
    hostname: str | None = None
    port: int | None = None

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
    r"\[(?P<ip>\d+\.\d+\.\d+\.\d+)\].+$"
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
    r"rhost=(?P<ip>\d+\.\d+\.\d+\.\d+|\S+).*"
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


def parse_header(line: str) -> dict | None:
    """ Parses header of an entry in the log file using a regex. """
    match = HEADER_PATTERN.match(line)
    if match:   
       return match.groupdict()

    return None

def parse_message(message: str) -> dict | None:
    """ Parses the message of an log entry usin regex. """
    for entry in MESSAGE_PATTERNS:
        match = entry.pattern.match(message)

        if match:
            return {
                "event": entry.event, **match.groupdict()
            }
    return None

def parse_timestamp(header: dict, year: int) -> datetime:
    """ Parses time and date from the log header and transforms it to datetime. """
    return datetime.strptime(
        f"{year} {header['month']} {header['day']} {header['time']}",
        "%Y %b %d %H:%M:%S"
    )

def create_log_entry(header: dict, message_data: dict, timestamp: datetime) -> LogEntry:
    """ Creates ordered LogEntry. """
    return LogEntry(
        timestamp=timestamp,
        host=header["host"],
        service=header["service"],
        pid=int(header["pid"]),
        event=message_data["event"],
        user=message_data.get("username"),
        ip=message_data.get("ip"),
        context=message_data.get("context")
    )

if __name__ == "__main__":
    log_entries = []
    file = sys.argv[1]
    unmatched = {}
    
    with open(file) as f: 
        for i, line in enumerate(f):
    #        if i >190:
    #            break
            
            header = parse_header(line.strip())
            if header is None:
                continue
            timestamp = parse_timestamp(header, year=2023)
            message = parse_message(header["message"])

            if message is None:

                raw_message = header["message"]
                unmatched[raw_message] = unmatched.get(raw_message, 0) + 1
                continue

            log_entry = create_log_entry(header, message, timestamp)
            log_entries.append(log_entry)            
    for message, count in unmatched.items():
        print(f"{count}x: {message}")
