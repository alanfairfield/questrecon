import os
import argparse
import nmap
from colorama import Fore, Back, Style
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import ThreadPoolExecutor, as_completed


# Function to print ASCII art 
def print_ascii_art():
    ascii_art = (Fore.YELLOW + Back.RED + Style.BRIGHT + r'''
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
''' + Style.RESET_ALL)

    print(ascii_art)
    print(Fore.WHITE + Back.MAGENTA + Style.BRIGHT + "\nThe quieter you become, the more you can hear.\n" + Style.RESET_ALL + Style.BRIGHT + '\n...\n')

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

# Create output directory if it doesn't already exist
def create_output_dir():
    if not os.path.isdir(output_dir):
        try:
            os.makedirs(f'{output_dir}/results/{target}')
            print(f"[+] Output directory created: {output_dir}/results/{target}")
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

# UDP Scan

def udp_nmap(target):
    nm = nmap.PortScanner()
    try:
        print(Fore.GREEN + f"[+] Running Quick UDP scan on {target}..." + Style.RESET_ALL)
        nm.scan(target, arguments=f"-sU -F -oN {output_dir}/results/{target}/quick_nmap_udp")  # Basic UDP scan, -F for only top 100 ports
        udp_ports = nm[target]['udp'].keys() if 'udp' in nm[target] else []
        print(f"[+] UDP Ports open on {target}: {list(udp_ports)}")

        # Tabulate open UDP ports and store them in a set
        open_udp = set(udp_ports)

        # Create directory structure for the host and associated ports
        create_directory_structure(target, open_udp)

    except Exception as e:
        print(f"[-] An error occured during scanning: {e}")
    return open_udp

# TCP quick scan of all ports
def tcp_nmap(target):
    # Create an nmap scanner object
    nm = nmap.PortScanner()

    # Run initial TCP sweep
    try:
        # TCP Scan
        print(Fore.GREEN + f"[+] Running Full TCP scan on {target} to determine which ports are open..." + Style.RESET_ALL)
        nm.scan(target, arguments=f"-p- -oN {output_dir}/results/{target}/quick_nmap_tcp")  # make it output to {output_dir}/results/{target}/quick_nmap_tcp
        tcp_ports = nm[target]['tcp'].keys() if 'tcp' in nm[target] else []
        print(f"[+] TCP Ports open on {target}: {list(tcp_ports)}")

        # Tabulate open TCP ports an store them in a set
        open_tcp = set(tcp_ports)

        # Create directory structure for the host and associated ports
        create_directory_structure(target, open_tcp)

    except Exception as e:
        print(f"[-] An error occurred during scanning: {e}")
    return open_tcp 

    
def tcp_service(open_tcp): 
    nm = nmap.PortScanner()
    for port in open_tcp:
        nm.scan(target, arguments=f"-p{port} -sV -sC -oN {output_dir}/results/{target}/{port}/tcp{port}_service_scan") 
        print(Fore.WHITE + Back.BLACK + Style.BRIGHT + f"[+] Service Scanning TCP Port {port} on target {target}" + Style.RESET_ALL)
        #print(f"*** Test Statement*** {tcp_service}") # how to access service name??

def udp_service(open_udp): 
    nm = nmap.PortScanner()
    for port in open_udp: 
        nm.scan(target, arguments=f"-p{port} -sV -sC -sU -oN {output_dir}/results/{target}/{port}/udp{port}_service_scan") 
        print(f"*** Test Statement udp_service *** Target = {target} UDP port = {port}")
    


# Handle multiple targets from a file

def scan_multiple_hosts(hosts, output_dir):
    with open(hosts, 'r') as file:
        hosts = [line.strip() for line in file.readlines() if line.strip()]

    for host in hosts:
        host_dir = Path(output_dir) / "results" / host 
        host_dir.mkdir(parents=True, exist_ok=True)

        with ProcessPoolExecutor() as executor:
            futures = {}
# Submit tasks for quick TCP and UDP scans for each host
            for host in hosts:
                futures_tcp = executor.submit(tcp_nmap, host)
                futures_udp = executor.submit(udp_nmap, host)
                futures[host] = {"tcp": futures_tcp, "udp": futures_udp}
# Process results and launch service scans
            for host, future_set in futures.items():
                try:
                    tcp_ports = future_set["tcp"].result()
                    udp_ports = future_set["udp"].result()
                    print(Fore.CYAN + f"[+] TCP Ports for {host}: {list(tcp_ports)}" + Style.RESET_ALL)
                    print(Fore.CYAN + f"[+] UDP Ports for {host}: {list(udp_ports)}" + Style.RESET_ALL)


                    # Run service scans for TCP Ports
                    for port in tcp_ports:

                        tcp_service(host, port)
                    for port in udp_ports:

                        udp_service(host, port)

                except Exception as e:
                    print(f"[-] Error processing scans for {host}: {e}")
       
                

    os.rmdir(f'{output_dir}/results/None') #Bug fix

            #TODO: find way to initiate service scans when reading host file (as opposed to scanning -t targets)


   

# Main 

def main():
    print_ascii_art()
    create_output_dir()

    if target:
        with ThreadPoolExecutor() as executor:
            futures_tcp = executor.submit(tcp_nmap, target) # in this case futures == 'open_tcp', the return value of tcp_nmap()
            for _ in as_completed([futures_tcp]):
                executor.submit(tcp_service, futures_tcp.result())
            
            futures_udp = executor.submit(udp_nmap, target)
            
            for _ in as_completed([futures_udp]):
                executor.submit(udp_service, futures_udp.result())
    elif hosts:
        scan_multiple_hosts(hosts, output_dir)

    else:
        print("[-] Please specify a target using '-t' or provide a hosts file using '-H'")

# Run the program
if __name__ == "__main__":
    main()

'''

#Access services associated with open ports??
for port in ports:
    tcp_service = nm[target][port]['name']
    print(f"Service Name(s) = {tcp_service}")

'''

