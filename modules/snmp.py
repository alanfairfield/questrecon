import subprocess
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Back, Style

def onesixtyone(host, protocol, port, output_dir):
    print(Fore.CYAN + Back.BLACK + Style.BRIGHT + f"[+] Enumerating SNMP on {host}:{port}" + Style.RESET_ALL)
    try:
        print("onesixtyone function test")
        wordlist_path = subprocess.getoutput(["locate common-snmp-community-strings | head -n 1"]) # can be replaced with any solid default wordlist
        subprocess.Popen([f"onesixtyone 192.168.56.6 -p {port} -q -c {wordlist_path} -o {output_dir}/results/{host}/{protocol}/{port}/snmp_public_strings_bruteforce.txt"], shell=True)
    except Exception as e:
        print(f"Error in onesixtyone snmp function: {e}")

def snmpwalk(host, protocol, port, output_dir):
    try:
        print(Fore.CYAN + Back.BLACK + Style.BRIGHT + f"[+] Running SNMPwalk on {host}:{port} using default string 'public'. See alternative strings to use @ {output_dir}/results/{host}/{protocol}/{port}/snmp_public_strings_bruteforce.txt" + Style.RESET_ALL)
        subprocess.Popen([f"snmpwalk -c public -v1 -t 10 {host} > {output_dir}/results/{host}/{protocol}/{port}/snmp_device_info"], shell=True)
    except Exception as e:
        print(f"Error in onesixtyone snmp function: {e}")

def all_snmp(host, protocol, port, output_dir):
    with ThreadPoolExecutor as executor:
        executor.submit(onesixtyone, host, protocol, port, output_dir)
        executor.submit(snmpwalk, host, protocol, port, output_dir)