import sys
import subprocess
from colorama import Fore, Back, Style
#from questrecon import Scanner

ascii_art = (Fore.LIGHTRED_EX + Back.BLACK + Style.BRIGHT + r'''
+~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-+                                                                   
|     (                           )   )\ )                               |
|   ( )\      (      (         ( /(  (()/(     (                         |
|   )((_)    ))\    ))\   (    )\())  /(_))   ))\    (     (     (       |
|  ((_)_    /((_)  /((_)  )\  (_))/  (_))    /((_)   )\    )\    )\ )    |
|   / _ \  (_))(  (_))   ((_) | |_   | _ \  (_))    ((_)  ((_)  _(_/(    |
|  | (_) | | || | / -_)  (_-< |  _|  |   /  / -_)  / _|  / _ \ | ' \))   |
|   \__\_\  \_,_| \___|  /__/  \__|  |_|_\  \___|  \__|  \___/ |_||_|    |
|                                                                        |
+~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-~-+                                                                        
''' + Style.RESET_ALL)

def dependancy_check():
    tools = ['seclists','feroxbuster','enum4linux-ng','snmpwalk','nmap','onesixtyone','hydra','nikto','wpscan']
    missing_tools = []

    for tool in tools:
        output = subprocess.getoutput(f"which {tool}")
        if '/usr/' not in output:
            missing_tools.append(tool)
        
    #print(' '.join(missing_tools))

    
    print(ascii_art)  
    print(Fore.YELLOW + Back.BLACK + Style.BRIGHT +f"[-] The following tools required to run QuestRecon are not found on your system: {' '.join(missing_tools)}\n\n" + Fore.GREEN + Back.BLACK + Style.BRIGHT + f"[+] Run: sudo apt-get update && sudo apt-get install {' '.join(missing_tools)}" + Style.RESET_ALL)
    sys.exit(1)