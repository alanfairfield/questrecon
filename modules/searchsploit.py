#Parse the output of individual-port-targeting nmap scans to get specific versions of running services, then run searchsploit, and return the output to a folder called "Vulnerabile_Version_Check"
import subprocess

def searchsploit(host, protocol, port, output_dir, product):
    subprocess.Popen([f"searchsploit --disable-color {product} > {output_dir}/results/{host}/{protocol}/{port}/searchsploit.txt"], shell=True) #save command to variable and print to confirm efficacy

    with open (f'{output_dir}/results/{host}/{protocol}/{port}/searchsploit.txt') as file:
        for line in file:
            if 'Exploit Title' in line:
                print(f"Possible vendor exploit(s) found for {product} on {host}:{port}! Results stored in {output_dir}/results/{host}/{protocol}/{port}/searchsploit.txt")
            else:
                break

              
# print statement doesn't work - investigate