import socket

# use scanme nmap as a target for testing
target = "scanme.nmap.org"

# use three example port nr to test first
ports = [22, 80, 443]

# loop ports for checking
for port in ports:
    # initialize socket object with connection-oriented TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    result = s.connect_ex((target, port))

    if result == 0:
        print(f"Port {port} is OPEN")
    else:
        print(f"Port {port} is CLOSED")

    s.close()
