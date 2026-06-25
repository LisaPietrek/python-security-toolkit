import socket
from datetime import datetime

""" TODO:
    add multithreading
    banner grabbing?
"""

def resolve_host(hostname: str) -> str:
    """ Resolve a hostname to an IP address."""
    target = socket.gethostbyname(hostname) 
    return target

def validate_port_range_input(port_range: str) -> tuple[int, int]:
    """ Vaidate and parse a port range. """
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

def print_header(target: str) -> None:
    """ Print scan info. """
    print("-" * 50)
    print("Scanning target: " + target)
    print("Scan started at: " + str(datetime.now()))
    print("-" * 50)
    
def port_scanner(target: str, port: int, timeout: float = 1.0) -> bool:
    """ Check whether TCP port id open. """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((target, port)) == 0

def port_range_scanner(target: str, start_port: int, end_port: int) -> list[int]:
    """ Scan a range of ports for a specified website.
    
    """
    open_ports = []
    # loop port range for checking
    for port in range(start_port, end_port+1):
        if port_scanner(target, port):
            open_ports.append(port)
    return open_ports
    

if __name__ == "__main__":
    step = 0
    while step < 1:

        hostname = input("Enter target hostname: ")
        try:
            target = resolve_host(hostname)
            step += 1
        except socket.gaierror: 
            print("Could not resolve host.")             
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
    open_ports = port_range_scanner(target, start_port, end_port)
    
    for port in open_ports:        
        print(f"Port {port} is OPEN")
