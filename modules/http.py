import subprocess

def test():
    print("Hi, I'm HTTP(s) service!")


def curl():
    t

def run_nikto(host, protocol, port, output_dir):
    print(f"Running nikto scan against {host}:{port}")
    subprocess.run([f"nikto -h {host} -o {output_dir}/results/{host}/{protocol}/{port}/nikto.txt"], shell=True)


def feroxbuster():
    t

def searchsploit():
    t


#TODO: Quiet output of nikto

