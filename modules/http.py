import subprocess
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from colorama import Fore, Back, Style
from modules.searchsploit import searchsploit
from modules.nmap_vuln import nmap_vuln


def curl(host, protocol, port, output_dir):
    subprocess.Popen([f"curl http://{host}:{port}/ > {output_dir}/results/{host}/{protocol}/{port}/{host}:{port}_curl"], shell=True)

def run_nikto(host, protocol, port, output_dir):
    print(Fore.MAGENTA + Back.BLACK + Style.BRIGHT + f"[+] Running nikto scan against {host}:{port}" + Style.RESET_ALL)
    subprocess.Popen([f"nikto -h {host} > {output_dir}/results/{host}/{protocol}/{port}/nikto.txt"], shell=True)

def run_feroxbuster(host, protocol, port, output_dir, wordlist):
    print(Fore.RED + Back.BLACK + Style.BRIGHT + f"[+] Running directory-brute force against {host}:{port}" + Style.RESET_ALL)
    subprocess.Popen([f"echo 'http://{host}:{port}/' | feroxbuster --quiet --auto-tune --stdin --parallel 10 -t 10 -w {wordlist} -x 'txt,html,php,asp,aspx,jsp' > {output_dir}/results/{host}/{protocol}/{port}/dir_brute_force.txt"], shell=True)
    
def all_http(host, protocol, port, output_dir, wordlist, product):
    with ThreadPoolExecutor() as executor:
        executor.submit(curl, host, protocol, port, output_dir)
        executor.submit(nmap_vuln, host, protocol, port, output_dir)
        executor.submit(run_feroxbuster, host, protocol, port, output_dir, wordlist)
        executor.submit(run_nikto, host, protocol, port, output_dir)
        executor.submit(searchsploit, host, protocol, port, output_dir, product)



