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
    
    target = socket.gethostbyname(url) 
    return target

def print_header(target):
    print("-" * 50)
    print("Scanning target: " + target)
    print("Scan started at: " + str(datetime.now()))
    print("-" * 50)

def validate_port_range_input(port_range):
    try:
        start_port, end_port = port_range.split()
        start_port = int(start_port)
        end_port = int(end_port)
    except ValueError:
        raise ValueError(
            "Port range must be separated by a space."
            )
    if start_port < 1 or end_port > 65535:
        raise ValueError(
            "Ports must be between 1 and 65535."
            )
    if start_port > end_port:
        raise ValueError(
            "Start port must be smaller than end port."
            )
    return start_port, end_port
    
def port_scanner(target, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        return sock.connect_ex((target, port)) == 0

def port_range_scanner(target, start_port, end_port):
    """ scan a range of ports for a specified website.
    
    """
    
    
    # loop port range for checking
    for port in range(start_port, end_port+1):
        # initialize socket object with connection-oriented TCP
        if port_scanner(target, port):
            print(f"Port {port} is OPEN")
    

if __name__ == "__main__":
    step = 0
    while step < 1:

        hostname = input("Enter target hostname: ")
        try:
            target = resolve_host(hostname)
            step += 1
        except socket.gaierror: 
            print("Could not resolve hostname.")             
    while step < 2:
        port_range = input(
            "Enter port range as integes (required format 'start end'): "
            )

        try:
            start_port, end_port = validate_port_range_input(port_range)
            step += 1
        except ValueError as err:
            print(f"Error: {err}")
    
    print_header(target)
    port_range_scanner(target, start_port, end_port)
