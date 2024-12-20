import os
import subprocess
from colorama import Fore, Back, Style
from concurrent.futures import ThreadPoolExecutor
from modules.searchsploit import searchsploit
from modules.nmap_vuln import nmap_vuln

def hydra_brute(host, protocol, port, output_dir, users, passwords): # define user and password lists
    try: # logic to handle file vs folder arguments

        if os.path.isfile(users) and os.path.isfile(passwords): # both are dir paths to credential file
            subprocess.Popen([f"hydra -t 4 -V -f -L {users} -P {passwords} ssh://{host} -s {port} > {output_dir}/results/{host}/{protocol}/{port}/ssh_brute_force.txt"], shell=True) 
        if os.path.isfile(users) and os.path.isfile(passwords) == False: # username is dir, pass is string
            subprocess.Popen([f"hydra -t 4 -V -f -L {users} -p {passwords} ssh://{host} -s {port} > {output_dir}/results/{host}/{protocol}/{port}/ssh_brute_force.txt"], shell=True) 
        if os.path.isfile(users) == False and os.path.isfile(passwords): # username is string, pass is dir
            subprocess.Popen([f"hydra -t 4 -V -f -l {users} -P {passwords} ssh://{host} -s {port} > {output_dir}/results/{host}/{protocol}/{port}/ssh_brute_force.txt"], shell=True) 
        else:                                                                   # both are strings
            subprocess.Popen([f"hydra -t 4-V -f -l {users} -p {passwords} ssh://{host} -s {port} > {output_dir}/results/{host}/{protocol}/{port}/ssh_brute_force.txt"], shell=True) 

    except Exception as e:
        print(f"Error in hydra_brute function: {e}")

    finally: # does not seem to be working
        with open (f"{output_dir}/results/{host}/{protocol}/{port}/ssh_brute_force.txt") as file:
            for line in file:
                print("ssh_brute test") # test line, remove later
                if '(valid pair found)' in line:
                    print(Fore.GREEN + Back.BLACK + Style.BRIGHT + f"[+++] Valid SSH credentials found on {host}:{port}. See results at: {output_dir}/results/{host}/{protocol}/{port}/ssh_brute_force.txt." + Style.RESET_ALL)
                    break # or pass?
                else:
                    pass


def all_ssh(host, protocol, port, output_dir, product, users, passwords):
    with ThreadPoolExecutor() as executor:
        executor.submit(searchsploit, host, protocol, port, output_dir, product)
        #executor.submit(nmap_vuln, host, protocol, port, output_dir)
        executor.submit(hydra_brute, host, protocol, port, output_dir, users, passwords)