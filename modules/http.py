import subprocess
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
import nmap


def curl(host, protocol, port, output_dir):
    subprocess.Popen([f"curl http://{host}:{port}/ -o {output_dir}/results/{host}/{protocol}/{port}/{host}:{port}_curl"], shell=True)

def run_nikto(host, protocol, port, output_dir):
    print(f"Running nikto scan against {host}:{port}")
    subprocess.Popen([f"nikto -h {host} > {output_dir}/results/{host}/{protocol}/{port}/nikto.txt"], shell=True)

def nmap_vuln(host, protocol, port, output_dir):
    print(f"Running Nmap Script-Scan against {host}:{port}")
    #nm = nmap.PortScanner
    command = ((f"nmap.PortScanner.scan({host}, arguments='-p{port} --script 'vuln' -oN {output_dir}/results/{host}/{protocol}/{port}/nmap_vuln_scan.txt'"))
    print(command) # Test statement
    try:
        subprocess.Popen([command], shell=True)
    except Exception as e:
        print(f"Error in nmap_vuln function: {e}")


def run_feroxbuster(host, protocol, port, output_dir, wordlist):
    print(f"Running directory-brute force against {host}:{port}")
    subprocess.Popen([f"echo 'http://{host}:{port}/' | feroxbuster --quiet --auto-tune --stdin --parallel 10 -t 10 -w {wordlist} -x 'txt,html,php,asp,aspx,jsp' > {output_dir}/results/{host}/{protocol}/{port}/dir_brute_force.txt"], shell=True)

def searchsploit(host, protocol, port, output_dir, product):
    subprocess.Popen([f"searchsploit --disable-color {product} > {output_dir}/results/{host}/{protocol}/{port}/searchsploit.txt"], shell=True) #save command to variable and print to confirm efficacy

    with open (f'{output_dir}/results/{host}/{protocol}/{port}/searchsploit.txt') as file:
        for line in file:
            if 'Exploits: No Results' in line:
                pass
            else:
                for _ in range(1):
                    print(f"Possible exploit found for {product} on {host}:{port}! Results stored in {output_dir}/results/{host}/{protocol}/{port}/searchsploit.txt")



    
    # command1 = subprocess.run([f"feroxbuster --quiet --auto-tune -u http://{host}:{port}/ -t 10 -w {wordlist} -x 'txt,html,php,asp,aspx,jsp' > {output_dir}/results/{host}/{protocol}/{port}/dir_brute_force.txt"], shell=True)
    # command2 = subprocess.run([f"echo 'http://{host}:{port}/' | feroxbuster --quiet --auto-tune --stdin --parallel 10 -t 10 -w {wordlist} -x 'txt,html,php,asp,aspx,jsp' > {output_dir}/results/{host}/{protocol}/{port}/dir_brute_force.txt"], shell=Truesubprocess.run([f"echo 'http://{host}:{port}/' | feroxbuster --quiet --auto-tune --stdin --parallel 10 -t 10 -w {wordlist} -x 'txt,html,php,asp,aspx,jsp' > {output_dir}/results/{host}/{protocol}/{port}/dir_brute_force.txt"], shell=True)


def all_http(host, protocol, port, output_dir, wordlist, product):
    with ThreadPoolExecutor() as executor:
        executor.submit(curl, host, protocol, port, output_dir)
        executor.submit(nmap_vuln, host, protocol, port, output_dir)
        executor.submit(run_feroxbuster, host, protocol, port, output_dir, wordlist)
        executor.submit(run_nikto, host, protocol, port, output_dir)
        executor.submit(searchsploit, host, protocol, port, output_dir, product)



