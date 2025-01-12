import os
import time
import subprocess
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from colorama import Fore, Back, Style
from modules.searchsploit import searchsploit


def curl(host, protocol, port, output_dir):
    subprocess.Popen([f"curl http://{host}:{port}/ > {output_dir}/results/{host}/{protocol}/{port}/{host}:{port}_curl.txt"], shell=True)
    #subprocess.Popen([f"curl http://{host}:{port}/robots.txt > {output_dir}/results/{host}/{protocol}/{port}/{host}:{port}_robots.txt"], shell=True)

def nmap_vuln(host, protocol, port, output_dir):
    print(Fore.CYAN + Back.BLACK + Style.BRIGHT + f"[+] Running Nmap Vuln scan against {host}:{port}" + Style.RESET_ALL)
    try:
        subprocess.Popen([f"nmap {host} -p{port} --script='vuln' > {output_dir}/results/{host}/{protocol}/{port}/nmap_{port}_vuln_scan.txt"], shell=True)
    except Exception as e:
        print(f"Error in nmap_vuln function: {e}")



def run_nikto(host, protocol, port, output_dir):
    print(Fore.MAGENTA + Back.BLACK + Style.BRIGHT + f"[+] Running nikto scan against {host}:{port}" + Style.RESET_ALL)
    subprocess.Popen([f"nikto -h {host} > {output_dir}/results/{host}/{protocol}/{port}/nikto.txt"], shell=True)

def run_wpscanner(host, protocol, port, output_dir, wordpress_dir):
    print(Fore.GREEN + Back.BLACK + Style.BRIGHT + f"[+] Wordpress instance detected on the server @ http://{host}:{port}/{wordpress_dir}. Enumerating for users and vulnerable plugins. See output at {output_dir}/results/{host}/{protocol}/{port}/wordpress_enum.txt" + Style.RESET_ALL)
    try:
        subprocess.Popen([f"wpscan --url http://{host}:{port}/{wordpress_dir} --enumerate p --enumerate u --plugins-detection aggressive -f cli-no-color -o {output_dir}/results/{host}/{protocol}/{port}/wordpress_enum.txt"], shell=True)
    except Exception as e:
        print(f"Error in run_wpscanner function: {e}")

def run_feroxbuster(host, protocol, port, output_dir, wordlist):
    print(Fore.RED + Back.BLACK + Style.BRIGHT + f"[+] Running directory-brute force against {host}:{port}" + Style.RESET_ALL)
    subprocess.Popen([f"echo 'http://{host}:{port}/' | feroxbuster --quiet --auto-tune --stdin --parallel 10 -t 10 -w {wordlist} -x 'txt,html,php,asp,aspx,jsp' > {output_dir}/results/{host}/{protocol}/{port}/dir_brute_force.txt"], shell=True)

    
def all_http(host, protocol, port, output_dir, wordlist, product, wordpress_dir):
    with ThreadPoolExecutor() as executor:
        executor.submit(curl, host, protocol, port, output_dir)
        executor.submit(run_feroxbuster, host, protocol, port, output_dir, wordlist)
        executor.submit(run_nikto, host, protocol, port, output_dir)
        executor.submit(searchsploit, host, protocol, port, output_dir, product)
    
    
        with open (f"{output_dir}/results/{host}/{protocol}/{port}/tcp_{port}_service_scan") as file:
            for line in file:
                if 'wordpress' in line:
                    wordpress_dir = 'wordpress'
                    with ThreadPoolExecutor() as executor:
                        executor.submit(run_wpscanner, host, protocol, port, output_dir, wordpress_dir)
                        break
                elif 'wp-config' in line:
                    wordpress_dir = 'wp-config' # see if .php is necessary or not
                    with ThreadPoolExecutor() as executor:
                        executor.submit(run_wpscanner, host, protocol, port, output_dir, wordpress_dir)
                    break
                elif 'wp-login' in line:
                    wordpress_dir = 'wp-login' # see if .php is necessary or not
                    with ThreadPoolExecutor() as executor:
                        executor.submit(run_wpscanner, host, protocol, port, output_dir, wordpress_dir)
                    break
                elif 'wp-admin' in line:
                    wordpress_dir = 'wp-admin' # see if .php is necessary or not
                    with ThreadPoolExecutor() as executor:
                        executor.submit(run_wpscanner, host, protocol, port, output_dir, wordpress_dir)
                    break
                if 'robots' in line:
                    subprocess.Popen([f"curl http://{host}:{port}/robots.txt > {output_dir}/results/{host}/{protocol}/{port}/{host}:{port}_robots.txt"], shell=True)
                if 'phpinfo.php' in line:
                    print(Fore.GREEN + Back.BLACK + Style.BRIGHT + f"[+] phpinfo.php directory found: http://{host}:{port}/phpinfo.php" + Style.RESET_ALL)
                if 'phpmyadmin' in line:
                    print(Fore.GREEN + Back.BLACK + Style.BRIGHT + f"[+] phpmyadmin.php directory found: http://{host}:{port}/phpmyadmin" + Style.RESET_ALL)
                else:
                    pass

    return wordpress_dir



