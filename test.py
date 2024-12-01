import os
import argparse
import time
import csv
import pandas as pd
import nmap
from colorama import Fore, Back, Style
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from modules import smb

smb.test() # module import test

# Define a class for Scanner object 
class Scanner:
    def __init__(self, target=None, hosts_file=None, output_dir=None):
        self.target = target
        self.hosts_file = hosts_file
        self.output_dir = output_dir

    def print_ascii_art(self):
        ascii_art = (Fore.WHITE + Back.BLACK + Style.BRIGHT + r'''
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
        print(Fore.WHITE + Back.BLACK + Style.BRIGHT + "The quieter you become, the more you can hear.\n" + Style.RESET_ALL + Style.BRIGHT + '\n...\n')

# Create output directory according to args.out
    def create_output_dir(self):
        if not os.path.isdir(self.output_dir):
            try:
                os.makedirs(f'{self.output_dir}/results')
                print(f"[+] Output directory created: {self.output_dir}/results")
            except Exception as e:
                print(f"[-] Something went wrong with the creation of the output directory! Error: {e}")

# UDP Nmap basic scan
    def udp_nmap(self, target):
        nm = nmap.PortScanner()
        try:
            target_dir = Path(self.output_dir) / "results" / target # Define output dir + results + target
            target_dir.mkdir(parents=True, exist_ok=True) # Create output dir +  results + target
            print(Fore.GREEN + f"[+] Running Quick UDP scan on {target}..." + Style.RESET_ALL)
            nm.scan(target, arguments=f"-sU -F -oN {target_dir}/quick_nmap_udp")
            udp_ports = nm[target]['udp'].keys() if 'udp' in nm[target] else []
            print(f"[+] UDP Ports open on {target}: {list(udp_ports)}")

            return set(udp_ports)
        
        except Exception as e:
            print(f"[-] An error occurred during basic UDP scan: {e}")
            return set()
        
# TCP Nmap basic scan
    def tcp_nmap(self, target):
        nm = nmap.PortScanner()
        try:
            target_dir = Path(self.output_dir) / "results" / target # Define output dir + results + target
            target_dir.mkdir(parents=True, exist_ok=True) # Create output dir +  results + target
    
            print(Fore.GREEN + f"[+] Running Full TCP scan on {target} to determine which ports are open..." + Style.RESET_ALL)
            nm.scan(target, arguments=f"-p- -oN {target_dir}/quick_nmap_tcp")
            tcp_ports = nm[target]['tcp'].keys() if 'tcp' in nm[target] else []
            print(f"[+] TCP Ports open on {target}: {list(tcp_ports)}")

            return set(tcp_ports)
        
        except Exception as e:
            print(f"[-] An error occurred during basic TCP scan: {e}")
            return set()
        
# TCP Service scan on tcp_ports 
    def tcp_service(self, target, port):
        nm = nmap.PortScanner()
        try:
            print(Fore.WHITE + Back.BLACK + Style.BRIGHT + f"[+] Service Scanning TCP Port {port} on target {target}" + Style.RESET_ALL)

            target_dir = Path(self.output_dir) / "results" / target / "tcp" / str(port)
            service_info_dir = target_dir / f"{port}_service_info.csv"
            target_dir.mkdir(parents=True, exist_ok=True)

            nm.scan(target, arguments=f"-p{port} -sV -sC -oN {target_dir}/tcp_{port}_service_scan")
            print(Fore.GREEN + f"[+] Service scan completed for TCP port {port} on {target}" + Style.RESET_ALL)

            # Get service information
            host_info = nm[target]  # Info about the target
        
            # Extract 'name' and 'product' for the given port
            product = host_info.get('tcp', {}).get(port, {}).get('product', 'Unknown')
            service_name = host_info.get('tcp', {}).get(port, {}).get('name', 'Unknown')

            # Write the CSV header only once
            if not service_info_dir.exists():
                with open(service_info_dir, 'w', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    writer.writerow(['host', 'protocol', 'port', 'name', 'product'])

            # Append the relevant information to the CSV
            with open(service_info_dir, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([target, 'tcp', port, service_name, product])

        except Exception as e:
            print(f"[-] TCP service scan error for {target}:{port}: {e}")

 


# UDP Service scan on udp_ports
    def udp_service(self, target, port):
        nm = nmap.PortScanner()
        try:
            print(Fore.WHITE + Back.BLACK + Style.BRIGHT + f"[+] Service Scanning UDP Port {port} on target {target}" + Style.RESET_ALL)
            target_dir = Path(self.output_dir) / "results" / target / "udp" / str(port)
            target_dir.mkdir(parents=True, exist_ok=True)
            service_info_dir = target_dir / f"{port}_service_info.csv"
        
            nm.scan(target, arguments=f"-p{port} -sV -sC -sU -oN {target_dir}/udp_{port}_service_scan")
            print(Fore.GREEN + f"[+] Service scan completed for UDP port {port} on {target}" + Style.RESET_ALL)

            # Get service information
            host_info = nm[target]
        
            # Extract 'name' and 'product' for the given port
            product = host_info.get('udp', {}).get(port, {}).get('product', 'Unknown')
            service_name = host_info.get('udp', {}).get(port, {}).get('name', 'Unknown')

            # Write the CSV header only once
            if not service_info_dir.exists():
                with open(service_info_dir, 'w', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    writer.writerow(['host', 'protocol', 'port', 'name', 'product'])

            # Append the relevant information to the CSV
            with open(service_info_dir, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([target, 'udp', port, service_name, product])

        except Exception as e:
            print(f"[-] UDP service scan error for {target}:{port}: {e}")



    def run(self):
        self.print_ascii_art()
        self.create_output_dir()

        if self.target:
            with ThreadPoolExecutor() as executor:
                futures = []
                futures.append(executor.submit(self.tcp_nmap, self.target))
                futures.append(executor.submit(self.udp_nmap, self.target))

                for future in as_completed(futures):
                    if future == futures[0]:
                        tcp_ports = future.result()
                        for port in tcp_ports:
                            executor.submit(self.tcp_service, self.target, port)
                    elif future == futures[1]:
                        udp_ports = future.result()
                        for port in udp_ports:
                            executor.submit(self.udp_service, self.target, port)
        elif self.hosts_file:
            self.scan_multiple_hosts()
        else:
            print("[-] Please specify a target using '-t <target>' or provide a hosts file using '-H <hostfile.txt>'")


# Concept: ServiceEnum does not need to use target or hosts file. By the time service scans are needed, target(s) scans are already completed and/or in-process.
# This class should act on the output file structure, using watchdog to monitor for csv files, and initiate service scans as new csv files appear, only if the 
# csv files contain services that are part of standard pentest enumeration

class ServiceEnum:

    def __init__(self, output_dir=None):
        self.output_dir = output_dir

    def find_csv_files(self, output_dir):
        csv_files = []
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                if file.endswith("_service_info.csv"):
                    csv_files.append(os.path.join(root, file))
        return csv_files
    
    def run(self, csv_files=None):
        print(csv_files)


if __name__ == "__main__":
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

    if not output_dir:
        output_dir = os.getcwd()
    if not target:
        print(f"[+] Provide a target using -t <target> or -H <hosts.txt>")

    scanner = Scanner(target=target, hosts_file=hosts, output_dir=output_dir)
    scanner.run()


    service_enum = ServiceEnum(output_dir=output_dir)
    service_enum.run()
    
