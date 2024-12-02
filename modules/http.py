import subprocess

def test():
    print("Hi, I'm HTTP(s) service!")


def curl():
    t

def run_nikto(host, protocol, port, output_dir):
    print(f"Running nikto scan against {host}:{port}")
    subprocess.run(["nikto", "-h", f"{host}", "-o", f"{output_dir}/{host}/{protocol}/{port}/nikto.txt"])

def feroxbuster():
    t

def searchsploit():
    t



'''subprocess.run([f"nikto -h {host} -o {output_dir}/{host}/{protocol}/{port}/nikto.out"])'''