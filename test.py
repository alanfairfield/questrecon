import os
import argparse
import nmap
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import as_completed
'''The other program version uses ProcessPoolExecutor to create distinct processes for multiple concurrent scans. This is good for operations that are more CPU-intensive 
(like nmap script scans, maybe dirbusting, etc.) but may have more unnecessary overhead for enumeration steps that are primarily bound by I/O, like basic nmap port-sweeps.
This program version, 'test.py', will use python3-nmap's async scan function for comparison.'''

# Function to print ASCII art 
def print_ascii_art():
    ascii_art = ('\033[92m' + r'''
+~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-+                                                                   
|     (                           )   )\ )                               |
|   ( )\      (      (         ( /(  (()/(     (                         |
|   )((_)    ))\    ))\   (    )\())  /(_))   ))\    (     (     (       |
|  ((_)_    /((_)  /((_)  )\  (_))/  (_))    /((_)   )\    )\    )\ )    |
|   / _ \  (_))(  (_))   ((_) | |_   | _ \  (_))    ((_)  ((_)  _(_/(    |
|  | (_) | | || | / -_)  (_-< |  _|  |   /  / -_)  / _|  / _ \ | ' \))   |
|   \__\_\  \_,_| \___|  /__/  \__|  |_|_\  \___|  \__|  \___/ |_||_|    |
|                                                                        |
+~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-+                                                                        
''' + '\033[92m')

    print(ascii_art)
    print("\nThe quieter you become, the more you can hear.\n")

# Arguments
parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target', help='Specify the target IP address, CIDR range, or hostname')
parser.add_argument('-H', '--hosts', help='Specify the path to a file containing host(s) separated by one or more spaces, tabs, or newlines')
parser.add_argument('-o', '--out', help='Specify the directory name path to output the results. E.g., ~/Pentests/Client1')
args = parser.parse_args()

# Variables from arguments
target = args.target
hosts = args.hosts
output_dir = args.out

# Create output directory if it doesn't alreadyexist
def create_output_dir():
    if not os.path.isdir(output_dir):
        try:
            os.makedirs(f'{output_dir}/results')
            print(f"[+] Output directory created: {output_dir}/results")
        except Exception as e:
            print(f"[-] Something went wrong with the creation of the output directory! Error: {e}")
   

# Create directory structure for each host and their ports
def create_directory_structure(host, ports):
    # Create directory for the host
    host_dir = Path(output_dir) / "results" / host
    host_dir.mkdir(parents=True, exist_ok=True)
    print(f"[+] Created directory for host: {host_dir}")

    # Create directories for each port under the host directory
    for port in ports:
        port_dir = host_dir / str(port)
        port_dir.mkdir(parents=True, exist_ok=True)
        print(f"[+] Created directory for port {port} under host {host}")

# UDP Scan

def udp_nmap(target):
    nma = nmap.PortScannerAsync()

    try:

        print(f"[+] Running Quick UDP scan on {target}...")
        nma.scan(target, arguments=f"-sU -oN {output_dir}/results/quick_nmap_udp",callback=create_directory_structure)  # Basic UDP scan
        udp_ports = nma[target]['udp'].keys() if 'udp' in nma[target] else []
        print(f"[+] UDP Ports open on {target}: {list(udp_ports)}")

        while nma.still_scanning():
            print("...", flush=True)
            nma.wait(10)

        # Tabulate open UDP ports and store them in a set
        open_udp = set(udp_ports)

        # Create directory structure for the host and associated ports
        create_directory_structure(target, open_udp)

    except Exception as e:
        print(f"[-] An error occured during scanning: {e}")
    return open_udp

# Function to scan the targets using python-nmap
def tcp_nmap(target):
    # Create an nmap scanner object
    nm = nmap.PortScanner()

    # Run a TCP scan and a UDP scan
    try:
        # TCP Scan
        print(f"[+] Running Quick TCP scan on {target}...")
        nm.scan(target, arguments=f"-oN {output_dir}/results/quick_nmap_tcp")  # Basic TCP scan

        tcp_ports = nm[target]['tcp'].keys() if 'tcp' in nm[target] else []
        print(f"[+] TCP Ports open on {target}: {list(tcp_ports)}")

        # Tabulate open TCP ports an store them in a set
        open_tcp = set(tcp_ports)

        # Create directory structure for the host and associated ports
        create_directory_structure(target, open_tcp)

    except Exception as e:
        print(f"[-] An error occurred during scanning: {e}")
        '''
        #Debug logic. Pass open_ports to another function
    for port in open_ports:
        print(port)
        '''
    return open_tcp
    


# Handle multiple targets from a file
def scan_multiple_hosts(hosts_file):

    with open(hosts_file, 'r') as file:
        hosts = [line.strip() for line in file.readlines() if line.strip()]

    for host in hosts:
        udp_nmap(host)
        tcp_nmap(host)

# Main 

def main():
    print_ascii_art()
    create_output_dir()

    if target:
        udp_nmap(target)
        tcp_nmap(target)

    elif hosts:
        scan_multiple_hosts(hosts)

    else:
        print("[-] Please specify a target using '-t' or provide a hosts file using '-H'")

'''logic to allow for no output_dir argument, and if no argument, create the parent results folder in current working dir:
if not output_dir:
        output_dir = Path.cwd()
'''
        

# Run the program
if __name__ == "__main__":
    main()
