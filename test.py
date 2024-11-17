import os
import argparse
import nmap
from pathlib import Path
from colorama import Fore, Back, Style
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

# Encapsulate arguments into a function rather than defining globally

def get_arguments():
    parser = argparse.ArgumentParser(description="Questrecon: A pentest enumeration and vulnerability assessment tool.")
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', help='Specify the target IP address, CIDR range, or hostname')
    parser.add_argument('-H', '--hosts', help='Specify the path to a file containing host(s) separated by one or more spaces, tabs, or newlines')
    parser.add_argument('-o', '--out', help='Specify the directory name path to output the results. E.g., ~/Pentests/Client1')
    return parser.parse_args()

# Define Targets as a class to handle individual targets (-t argument), as well as to enable the efficient scanning of -H hosts being recognized as a group of targets

class Target:
    def __init__(self, IP, output_dir):
        self.IP = IP
        self.output_dir = Path(output_dir) / "results" / IP
        self.open_tcp = set()
        self.open_udp = set()
        self.services = {}
    
    def setup_output_directory(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def create_port_directory(self, port):
        """Create a subdirectory for port in ports, for target in target(s)"""
        port_dir = self.output_dir / str(port)
        port_dir.mkdir(parents=True, exist_ok=True)

    def run_tcp_scan(self):
        print(Fore.GREEN + f"[+] Running Full TCP scan on {self.IP} to determine which ports are open..." + Style.RESET_ALL)
        open_tcp = tcp_nmap(self.IP, self.output_dir / "quick_nmap_tcp")
        self.open_tcp.update(open_tcp)

    def run_udp_scan(self):
        print(Fore.GREEN + f"[+] Running top-100-port UDP scan on {self.IP} to determine which ports are open..." + Style.RESET_ALL)
        open_udp = udp_nmap(self.IP, self.output_dir / "quick_nmap_udp")
        self.open_udp.update(open_udp)
    
    def run_service_scan(self):
        for port in self.open_tcp:
            tcp_service([port])
        for port in self.open_udp:
            udp_service([port])

    def __str__(self):
        return (f"Target(IP={self.IP}, TCP={list(self.open_tcp)}, "
                f"UDP={list(self.open_udp)}, Services={self.services})")
    
# HostManager class 

class HostManager:
    def __init__(self, host_file, output_dir):
        self.targets = []
        self.output_dir = output_dir
        self.load_hosts(host_file)

    def load_hosts(self, host_file):
        with open(host_file, 'r') as file:
            ip = [line.strip() for line in file.readlines() if line.strip()]
            if ip:
                self.targets.append(Target(ip, self.output_dir))
    
    def run_scans(self):
        with ProcessPoolExecutor() as executor:
            futures = {executor.submit(self.scan_target, target): target for target in self.targets}
            for future in as_completed(futures):
                target = futures[future]
                try:
                    future.result()
                    print(f"[+] Scans completed for {target.IP}")
                except Exception as e:
                    print(f"[-] Error scanning {target.IP}: {e}")

    @staticmethod
    def scan_target(target):
        target.setup_output_directory()
        target.run_tcp_scan()
        target.run_udp_scan()
        target.run_service_scan()

# TCP scan function

def tcp_nmap(target, output_file):
    nm = nmap.PortScanner()
    try:
        print(Fore.GREEN + f"[+] Running Full TCP scan on {target} to determine which ports are open..." + Style.RESET_ALL)
        nm.scan(target, arguments=f"-p- -oN {output_file}") 
        tcp_ports = nm[target]['tcp'].keys() if 'tcp' in nm[target] else []
        print(f"[+] TCP Ports open on {target}: {list(tcp_ports)}")
        # Tabulate open TCP ports an store them in a set
        open_tcp = set(tcp_ports)
        
    except Exception as e:
        print(f"[-] Error in TCP scan for {target}: {e}")

        return open_tcp
        
# UDP scan function

def udp_nmap(target, output_file):
    nm = nmap.PortScanner()
    try:
        print(Fore.GREEN + f"[+] Running Full TCP scan on {target} to determine which ports are open..." + Style.RESET_ALL)
        nm.scan(target, arguments=f"-sU -F {output_file}")  
        udp_ports = nm[target]['tcp'].keys() if 'udp' in nm[target] else []
        print(f"[+] TCP Ports open on {target}: {list(udp_ports)}")
        # Tabulate open TCP ports an store them in a set
        open_udp = set(udp_ports) 
        
    except Exception as e:
        print(f"[-] Error in TCP scan for {target}: {e}")

        return open_udp
        
# TCP service scan function
def tcp_service(target, open_tcp, output_file):
    nm = nmap.PortScanner()
    for port in open_tcp: 
        try:
            nm.scan(target, arguments=f"-p{port} -sV -sC -oN {output_file}")
            print(Fore.WHITE + Back.BLACK + Style.BRIGHT + f"[+] Service scan for TCP port {port} on {target}" + Style.RESET_ALL)
        except Exception as e:
            print(f"[-] Err in TCP service scan for {target}:{port}: {e}")

# UDP service scan function
def udp_service(target, open_udp, output_file):
    nm = nmap.PortScanner()
    for port in open_udp:
        try:
            nm.scan(target, arguments=f"-p{port} -sV -sC -sU -oN {output_file}")
            print(Fore.WHITE + Back.BLACK + Style.BRIGHT + f"[+] Service scan for UDP port {port} on {target}" + Style.RESET_ALL)
        except Exception as e:
            print(f"[-] Error in UDP service scan for {target}:{port}: {e}")

# Main function
def main():
    args = get_arguments()
    print_ascii_art()

    if args.target:
        print(f"[+] Starting enumeration for single target: {args.target}")
        t = Target(args.target, args.out)
        t.setup_output_directory()
        t.run_tcp_scan()
        t.run_udp_scan()
        t.run_service_scan()
        print(f"[+] Scan completed for {args.target}")
        print(t)
    elif args.hosts:
        print(f"[+] Starting scan from host-file: {args.hosts}")
        manager = HostManager(args.hosts, args.out)
        manager.run_scans()
        print("[+] All nmap scans completed.")

if __name__ == "__main__":
    main()
