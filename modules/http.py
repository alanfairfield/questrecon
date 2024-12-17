import subprocess
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor


def curl(host, protocol, port, output_dir):
    subprocess.Popen([f"curl http://{host}:{port}/ -o {output_dir}/results/{host}/{protocol}/{port}/{host}:{port}_curl"], shell=True)

def run_nikto(host, protocol, port, output_dir):
    print(f"Running nikto scan against {host}:{port}")
    subprocess.Popen([f"nikto -h {host} > {output_dir}/results/{host}/{protocol}/{port}/nikto.txt"], shell=True)

def nmap_vuln(host, protocol, port, output_dir):
    print(f"Running Nmap Script-Scan against {host}:{port}")
    sq = r"'"
    #command = (f"nm.scan{lp}{host}, arguments=" + f"{dq}-p{port} --script {sq}vuln{sq} -oN {output_dir}/results/{host}/{protocol}/{port}/nmap_{port}_vuln_scan.txt{dq}{rp}")
    #print(f"TEST nmap vuln scan command == {command}") # Test statement
    # nm.scan(target, arguments=f"-sU -F -oN {target_dir}/quick_nmap_udp")
    # nm.scan(192.168.56.5, arguments="-p80 --script 'vuln' -oN /home/quest/Github_Repo/questrecon/results/192.168.56.5/tcp/80/nmap_80_vuln_scan.txt")
    try:
        subprocess.Popen([f"nmap {host} -p{port} --script {sq}vuln{sq} -oN {output_dir}/results/{host}/{protocol}/{port}/nmap_{port}_vuln_scan.txt"], shell=True)
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



