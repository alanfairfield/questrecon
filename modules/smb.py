import subprocess
from colorama import Fore, Back, Style
from concurrent.futures import ThreadPoolExecutor
from modules.searchsploit import searchsploit

def enum4linuxng(host, protocol, port, output_dir, users, passwords):
    print(Fore.LIGHTRED_EX + Back.BLACK + Style.BRIGHT + f"[+] Attempting to authenticate to SMB on {host}:{port}" + Style.RESET_ALL)
    try:
        subprocess.Popen([f"enum4linux -u 'guest' -p '' -a {host} -o {output_dir}/results/{host}/{protocol}/{port}/smb_enum.txt"], shell=True)
    except Exception as e:
        print(f"Error in smb enum function: {e}")

def all_smb(host, protocol, port, output_dir, product, users, passwords):
    with ThreadPoolExecutor() as executor:
        executor.submit(searchsploit, host, protocol, port, output_dir, product)
        executor.submit(enum4linuxng, host, protocol, port, output_dir, users, passwords)


'''
try:
    if not users

'''