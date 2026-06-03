import socket
import sys
from datetime import datetime

""" TODO:
    improve exception handling, output handling
    add multithreading
    banner grabbing?
    validate input port range
"""

def resolve_host(url):
    return socket.gethostbyname(url) 

def print_header(target):
    print("-" * 50)
    print("Scanning target: " + target)
    print("Scan started at: " + str(datetime.now()))
    print("-" * 50)
    
def port_scanner(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex((target, port)) == 0

def port_range_scanner(url, port_to_check):
    """ PORT SCANNER: checks if ports in a given range for a  specified website are open
    
    """
    start_port, end_port = port_to_check.split(" ")
    
    
    # try to get the IP for the website to avoid the addition of the overhead DNS lookup - may slow down the initial connection
    try: 
        target = resolve_host(url)
    except socket.gaierror: 
    
        # this means could not resolve the host 
        print ("there was an error resolving the host")
        # stop here in case of a problem
        sys.exit() 
    
    
    print_header(target)
    # handle exceptions
    try:
        # loop port range for checking
        for port in range(int(start_port), int(end_port)+1):
            # initialize socket object with connection-oriented TCP
            if port_scanner(target, port):
                print(f"Port {port} is OPEN")
            # else:
            #     print(f"Port {port} is CLOSED")
        
    
    except KeyboardInterrupt:
        print("\nExiting Program.")
        sys.exit()
    except socket.error:
       print("\nServer not responding.")
       sys.exit()	

if __name__ == "__main__":
    # use scanme nmap as a target for testing
    # use the url as input for the target website, you want to check
    url = input("Enter target url: ")
    port_to_check = input("Enter port range as integes (required format 'start end'): ")

    port_range_scanner(url, port_to_check)
