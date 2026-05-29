import socket
import sys
from datetime import datetime

# use scanme nmap as a target for testing
# use the URL as input for the target website, you want to check
#URL = sys.argv[1]
URL = input("Enter target URL: ")

# try to get the IP for the website to avoid the addition of the overhead DNS lookup - may slow down the initial connection
try: 
    target = socket.gethostbyname(URL) 
except socket.gaierror: 

    # this means could not resolve the host 
    print ("there was an error resolving the host")
    # stop here in case of a problem
    sys.exit() 

# make output a bit more informative
print("-" * 50)
print("Scanning target: " + target)
print("Scan started at: " + str(datetime.now()))
print("-" * 50)


# loop port range for checking
for port in range(1, 1500):
    # initialize socket object with connection-oriented TCP
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)

    result = s.connect_ex((target, port))

    if result == 0:
        print(f"Port {port} is OPEN")
    else:
        print(f"Port {port} is CLOSED")

    s.close()
