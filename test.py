import os
import argparse
import nmap
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures import ThreadPoolExecutor, as_completed


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

class TARGET:
    
    def __init__(self, IP, open_tcp, open_udp):
        self.IP = IP
        self.open_tcp = set(open_tcp)
        self.open_udp = set(open_udp)

    

  
        



# Main 

def main():
    print_ascii_art()
    create_output_dir()

    if target:
        with ThreadPoolExecutor() as executor:
            futures_tcp = executor.submit(tcp_nmap, target) # in this case we are essentially equating futures to 'open_tcp', the return value of tcp_nmap()
            for future in as_completed([futures_tcp]):
                #tcp_service(future)
                executor.submit(tcp_service, futures_tcp.result())
                print(future.result()) # Test print statement
            
            futures_udp = executor.submit(udp_nmap, target)
            for future in as_completed([futures_udp]):
                executor.submit(udp_service, futures_udp.result())
                



    elif hosts:
        scan_multiple_hosts(hosts)
    else:
        print("[-] Please specify a target using '-t' or provide a hosts file using '-H'")

# Run the program
if __name__ == "__main__":
    main()