import subprocess

tools = ['seclists','feroxbuster','enum4linux-ng','snmpwalk', ]

output = subprocess.getoutput("which seclists")