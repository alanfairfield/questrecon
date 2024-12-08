import subprocess


def curl(host, protocol, port, output_dir):
    subprocess.run([f"curl http://{host}:{port}/ -o {output_dir}/results/{host}/{protocol}/{port}/{host}:{port}_curl"], shell=True)

def run_nikto(host, protocol, port, output_dir):
    print(f"Running nikto scan against {host}:{port}")
    subprocess.run([f"nikto -h {host} > {output_dir}/results/{host}/{protocol}/{port}/nikto.txt"], shell=True)


def run_feroxbuster(host, protocol, port, output_dir, wordlist):
    print(f"Running directory-brute force against {host}:{port}")
    subprocess.run([f"feroxbuster --quiet --auto-tune -u http://{host}:{port}/ -t 10 -w {wordlist} -x 'txt,html,php,asp,aspx,jsp' > {output_dir}/results/{host}/{protocol}/{port}/dir_brute_force.txt"], shell=True)

def searchsploit(host, protocol, port, output_dir, product):
    subprocess.run([f"searchsploit --disable-color {product} > {output_dir}/results/{host}/{protocol}/{port}/searchsploit.txt"], shell=True) #save command to variable and print to confirm efficacy

    with open (f'{output_dir}/results/{host}/{protocol}/{port}/searchsploit.txt') as file:
        for line in file:
            if 'No Results' in line:
                pass
            else:
                print(f"Possible exploit found for {product} on {host}:{port}! Results stored in {output_dir}/results/{host}/{protocol}/{port}/searchsploit.txt")


#Idea for feroxbuster: use bash command to find path of wordlist file, and pipe that file path to the default wordlists value, to avoid finicky file locations 
