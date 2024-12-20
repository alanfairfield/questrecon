import subprocess
from colorama import Fore, Back, Style
from modules.searchsploit import searchsploit

def nmap_vuln(host, protocol, port, output_dir):
    print(Fore.CYAN + Back.BLACK + Style.BRIGHT + f"[+] Running Nmap Vuln scan against {host}:{port}" + Style.RESET_ALL)
    try:
        subprocess.Popen([f"nmap {host} -p{port} --script 'vuln' > {output_dir}/results/{host}/{protocol}/{port}/nmap_{port}_vuln_scan.txt"], shell=True)
    except Exception as e:
        print(f"Error in nmap_vuln function: {e}")