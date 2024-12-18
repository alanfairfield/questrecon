import os
import subprocess
from colorama import Fore, Back, Style
from modules.searchsploit import searchsploit
from concurrent.futures import ThreadPoolExecutor

def nmap_vuln(host, protocol, port, output_dir):
    print(Fore.CYAN + Back.BLACK + Style.BRIGHT + f"[+] Running Nmap Vuln scan against {host}:{port}" + Style.RESET_ALL)
    sq = r"'"
    try:
        subprocess.Popen([f"nmap {host} -p{port} --script {sq}vuln{sq} > {output_dir}/results/{host}/{protocol}/{port}/nmap_{port}_vuln_scan.txt"], shell=True)
    except Exception as e:
        print(f"Error in nmap_vuln function: {e}")

def hydra_brute(host, protocol, port, output_dir, username_list, password_list): # define user and password lists
    try: # logic to handle file vs folder arguments

        if os.path.isfile(username_list) and os.path.isfile(password_list): # both are dir paths to credential file
            subprocess.Popen([f"hydra -t 1 -V -f -L {username_list} -P {password_list} ftp://{host} > {output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt"], shell=True) 
        if os.path.isfile(username_list) and os.path.isfile(password_list) == False: # username is dir, pass is string
            subprocess.Popen([f"hydra -t 1 -V -f -L {username_list} -p {password_list} ftp://{host} > {output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt"], shell=True) 
        if os.path.isfile(username_list) == False and os.path.isfile(password_list): # username is string, pass is dir
            subprocess.Popen([f"hydra -t 1 -V -f -l {username_list} -P {password_list} ftp://{host} > {output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt"], shell=True) 
        else:                                                                   # both are strings
            subprocess.Popen([f"hydra -t 1 -V -f -l {username_list} -p {password_list} ftp://{host} > {output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt"], shell=True) 


    except Exception as e:
        print(f"Error in hydra_brute function: {e}")

    finally:
        with open (f"{output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt") as file:
            for line in file:
                if 'valid pair found' in line:
                    print(Fore.GREEN + Back.BLACK + Style.BRIGHT + f"[+++] Valid FTP credentials found on {host}:{port}. See results at: {output_dir}/results/{host}/{protocol}/{port}/ftp_brute_force.txt." + Style.RESET_ALL)


def all_ftp(host, protocol, port, output_dir, product, username_list, password_list):
    with ThreadPoolExecutor() as executor:
        executor.submit(searchsploit, host, protocol, port, output_dir, product)
        executor.submit(nmap_vuln, host, protocol, port, output_dir)
        executor.submit(hydra_brute, host, protocol, port, output_dir, username_list, password_list)

        



