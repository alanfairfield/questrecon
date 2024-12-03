import subprocess

def test():
    print("Hi, I'm HTTP(s) service!")


def curl():
    t

def run_nikto(host, protocol, port, output_dir):
    print(f"Running nikto scan against {host}:{port}")
    subprocess.run([f"nikto -h {host} > {output_dir}/results/{host}/{protocol}/{port}/nikto.txt"], shell=True)


def run_feroxbuster(host, protocol, port, output_dir, wordlist):
    print(f"Running directory-brute force against {host}:{port}")
    subprocess.run([f"feroxbuster -u http://{host}:{port}/ -t 10 -w {wordlist} -x 'txt,html,php,asp,aspx,jsp' > {output_dir}/results/{host}/{protocol}/{port}/dir_brute_force.txt"], shell=True)

def searchsploit():
    t


#TODO: Quiet output of feroxbuster, and exclude 404 status codes
# + Start Time:         2024-12-02 18:01:18 (GMT-5)
