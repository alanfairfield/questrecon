import sys
import subprocess
from colorama import Fore, Back, Style
from questrecon import Scanner


def dependancy_check(): 
    tools = ['seclists','feroxbuster','enum4linux-ng','snmpwalk']
    missing_tools = []

    for tool in tools:
        output = subprocess.getoutput(f"which {tool}")
        if '/usr/' not in output:
            missing_tools.append(tool)
            Scanner.print_ascii_art(self=None)

    for missing_tool in missing_tools:
        
        print(Fore.YELLOW + Back.BLACK + Style.BRIGHT +f"[-] {missing_tool} not found on your system. Run: sudo apt-get install {missing_tool}" + Style.RESET_ALL)
        
        sys.exit(1)