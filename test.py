import os
import argparse
import time
import csv
import pandas as pd
import nmap
from colorama import Fore, Back, Style
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# questrecon modules
import modules.smb
from modules.http import run_nikto
modules.http.test()  # Module import test

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

    def create_output_dir(self):
        if not os.path.isdir(self.output_dir):
            try:
                os.makedirs(f'{self.output_dir}') # if filesystem creation glitches, make this line: os.makedirs(f'{self.output_dir}/results') and change the definition of output dir in main() to 
                print(f"[+] Output directory created: {self.output_dir}")
            except Exception as e:
                print(f"[-] Something went wrong with the creation of the output directory! Error: {e}")

    def udp_nmap(self, target):
        nm = nmap.PortScanner()
        try:
            target_dir = Path(self.output_dir) / "results" / target
            target_dir.mkdir(parents=True, exist_ok=True)
            print(Fore.GREEN + f"[+] Running Quick UDP scan on {target}..." + Style.RESET_ALL)
            nm.scan(target, arguments=f"-sU -F -oN {target_dir}/quick_nmap_udp")
            udp_ports = nm[target]['udp'].keys() if 'udp' in nm[target] else []
            print(f"[+] UDP Ports open on {target}: {list(udp_ports)}")

            return set(udp_ports)
        
        except Exception as e:
            print(f"[-] An error occurred during basic UDP scan: {e}")
            return set()
        
    def tcp_nmap(self, target):
        nm = nmap.PortScanner()
        try:
            target_dir = Path(self.output_dir) / "results" / target
            target_dir.mkdir(parents=True, exist_ok=True)
    
            print(Fore.GREEN + f"[+] Running Full TCP scan on {target} to determine which ports are open..." + Style.RESET_ALL)
            nm.scan(target, arguments=f"-p- -oN {target_dir}/quick_nmap_tcp")
            tcp_ports = nm[target]['tcp'].keys() if 'tcp' in nm[target] else []
            print(f"[+] TCP Ports open on {target}: {list(tcp_ports)}")

            return set(tcp_ports)
        
        except Exception as e:
            print(f"[-] An error occurred during basic TCP scan: {e}")
            return set()
        
    def tcp_service(self, target, port):
        nm = nmap.PortScanner()
        try:
            print(Fore.WHITE + Back.BLACK + Style.BRIGHT + f"[+] Service Scanning TCP Port {port} on target {target}" + Style.RESET_ALL)

            target_dir = Path(self.output_dir) / "results" / target / "tcp" / str(port)
            service_info_dir = target_dir / f"{port}_service_info.csv"
            target_dir.mkdir(parents=True, exist_ok=True)

            nm.scan(target, arguments=f"-p{port} -sV -sC -oN {target_dir}/tcp_{port}_service_scan")
            print(Fore.GREEN + f"[+] Service scan completed for TCP port {port} on {target}" + Style.RESET_ALL)

            host_info = nm[target]
            product = host_info.get('tcp', {}).get(port, {}).get('product', 'Unknown')
            service_name = host_info.get('tcp', {}).get(port, {}).get('name', 'Unknown')

            if not service_info_dir.exists():
                with open(service_info_dir, 'w', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    writer.writerow(['host', 'protocol', 'port', 'name', 'product'])

            with open(service_info_dir, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([target, 'tcp', port, service_name, product])

        except Exception as e:
            print(f"[-] TCP service scan error for {target}:{port}: {e}")
 
    def udp_service(self, target, port):
        nm = nmap.PortScanner()
        try:
            print(Fore.WHITE + Back.BLACK + Style.BRIGHT + f"[+] Service Scanning UDP Port {port} on target {target}" + Style.RESET_ALL)
            target_dir = Path(self.output_dir) / "results" / target / "udp" / str(port)
            target_dir.mkdir(parents=True, exist_ok=True)
            service_info_dir = target_dir / f"{port}_service_info.csv"
        
            nm.scan(target, arguments=f"-p{port} -sV -sC -sU -oN {target_dir}/udp_{port}_service_scan")
            print(Fore.GREEN + f"[+] Service scan completed for UDP port {port} on {target}" + Style.RESET_ALL)

            host_info = nm[target]
        
            product = host_info.get('udp', {}).get(port, {}).get('product', 'Unknown')
            service_name = host_info.get('udp', {}).get(port, {}).get('name', 'Unknown')

            if not service_info_dir.exists():
                with open(service_info_dir, 'w', newline='') as csv_file:
                    writer = csv.writer(csv_file)
                    writer.writerow(['host', 'protocol', 'port', 'name', 'product'])

            with open(service_info_dir, 'a', newline='') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow([target, 'udp', port, service_name, product])

        except Exception as e:
            print(f"[-] UDP service scan error for {target}:{port}: {e}")

    # Scan hosts from host files, treating host in hosts as target
    def scan_multiple_hosts(self):
        with open(self.hosts_file, 'r') as file:
            host_list = [line.strip() for line in file if line.strip()]

        with ThreadPoolExecutor() as executor:
            future_to_host = {} # Empty dict to store future objects
            for host in host_list:
                print(Fore.CYAN + f"[+] Starting scans for host: {host}" + Style.RESET_ALL)
                future_to_host[executor.submit(self.tcp_nmap, host)] = (host, 'tcp') # Quick TCP
                future_to_host[executor.submit(self.udp_nmap, host)] = (host, 'udp') # Quick UDP

            for future in as_completed(future_to_host): 
                host, scan_type = future_to_host[future]
                try:
                    ports = future.result()
                    if scan_type == 'tcp':
                        print(Fore.GREEN + f"[+] TCP Ports open on {host}: {list(ports)}" + Style.RESET_ALL)
                        for port in ports:
                            executor.submit(self.tcp_service, host, port)
                    elif scan_type == 'udp':
                        print(Fore.GREEN + f"[+] UDP Ports open on {host}: {list(ports)}" + Style.RESET_ALL)
                        for port in ports:
                            executor.submit(self.udp_service, host, port)
                except Exception as e:
                    print(f"[-] Error processing {scan_type.upper()} scan for {host}: {e}")

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

class ServiceEnum:
    def __init__(self, output_dir):
        self.output_dir = output_dir

    def handle_service_enumeration(self, host, protocol, port, service_name, product):
        print(Fore.CYAN + Back.BLACK + Style.BRIGHT + f"[+] Service found: {host}:{port} ({protocol}) - {service_name} ({product})"+ Style.RESET_ALL + Style.BRIGHT)

    def process_csv(self, file_path):
        retries = 3 # increase if low bandwidth testing multiplies instance of errors
        while retries > 0:
            try:
                # Check if the file is still being written (size stable for a certain period)
                initial_size = os.path.getsize(file_path)
                time.sleep(1)  
                final_size = os.path.getsize(file_path)
                if initial_size != final_size:
                    print(f"File {file_path} is still being written, retrying...")
                    retries -= 1
                    time.sleep(5)  # Wait before retrying
                    continue

                df = pd.read_csv(file_path)
                if {'host', 'protocol', 'port', 'name', 'product'}.issubset(df.columns):
                    for _, row in df.iterrows():
                        host = row['host']
                        protocol = row['protocol']
                        port = row['port']
                        service_name = row['name']
                        product = row['product']

                        """Service Detection Logic- Pentest tools and procedures called from /modules"""

                        if protocol == 'tcp' and 'http' in service_name:
                            self.handle_service_enumeration(host, protocol, port, service_name, product)
                            modules.http.test() # test statement - remove later
                            run_nikto(host, protocol, port, output_dir)
                        
                else:
                    print(f"Skipping {file_path}: Missing necessary columns.")
                break  # Exit retry loop if successful
            except Exception as e:
                print(f"Error processing file {file_path}: {e}")
                retries -= 1
                time.sleep(5)  # Wait before retrying

        if retries == 0:
            print(f"Failed to process {file_path} after multiple attempts.")

    def on_created(self, event):
        """Handle newly created files."""
        if event.is_directory:
            return

        if event.src_path.endswith('.csv'):
            #print(f"[+] New CSV file detected: {event.src_path}") # test statement
            self.process_csv(event.src_path)

    def start_watching(self):
        event_handler = FileSystemEventHandler()
        event_handler.on_created = self.on_created
        observer = Observer()
        observer.schedule(event_handler, self.output_dir, recursive=True)
        observer.start()

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()

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
    output_dir = args.out or Path.cwd() / "results" 
    #print(output_dir)

    if not target and not hosts:
        print(f"[+] Provide a target using -t <target> or -H <hosts.txt>")

    # Create Scanner and ServiceEnum objects
    scanner = Scanner(target=target, hosts_file=hosts, output_dir=output_dir)
    service_enum = ServiceEnum(output_dir)

    # Start scanning and watching concurrently
    with ThreadPoolExecutor() as executor:
        futures = [
            executor.submit(scanner.run),  # Start scanning
            executor.submit(service_enum.start_watching)  # Start file watching
        ]

        # Wait for both tasks to complete
        for future in futures:
            future.result()
