import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

""" TODO:
    banner grabbing
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
    
    
def scan_single_port(args: tuple[str, int]) -> dict:
    """ Check whether TCP port is open. """
    target, port = args
    out = dict()
    is_open = False
    banner = None
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        
        if sock.connect_ex((target, port)) == 0:
            is_open = True

            # Receive the banner and decode it to a string
            try: 
                banner = sock.recv(1024).decode().strip()
            except (socket.timeout, UnicodeDecodeError):
                pass
    out = {"port": port,
           "open": is_open,
           "banner": banner }
        
    return out
              

    
def scan_port_range(target: str, start_port: int, end_port: int) -> dict:
    """ Scan a range of ports for a specified website.
    
    """
    ports = range(start_port, end_port+1)
    scan_tasks = ((target, port) 
                  for port in ports)
    max_workers = min(100, len(ports))
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # use submit instead of map?
        results = executor.map(scan_single_port,  scan_tasks)
        
    return results 
    
    
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
    scan_results = scan_port_range(target, start_port, end_port)
    
    for port in scan_results:
        if port["open"]:        
            print(port) 
