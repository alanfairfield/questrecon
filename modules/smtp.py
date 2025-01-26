import subprocess
from colorama import Fore, Back, Style

def smtp_vuln(host, protocol, port, output_dir):
    print(Fore.CYAN + Back.BLACK + Style.BRIGHT + f"[+] Enumerating SMTP on {host}:{port}" + Style.RESET_ALL)
    try:
        subprocess.Popen([f"nmap {host} -p{port} --script 'smtp-*' > {output_dir}/results/{host}/{protocol}/{port}/nmap_{port}_smtp_all.txt"], shell=True)
    except Exception as e:
        print(f"Error in smtp_vuln function: {e}")