# QuestRecon
## Multi-Protocol Network Scanner and Service Enumerator


## Overview
This tool is a **Multi-Protocol Network Scanner and Service Enumerator** designed for penetration testers and security researchers. It automates network scanning, port enumeration, and service-specific testing using the Nmap library and integrated modules for common protocols.

The tool supports:
- **TCP/UDP Scanning**: Quickly discover open ports.
- **Service Enumeration**: Identify services running on discovered ports and perform protocol-specific enumeration.
- **Multi-Host Support**: Scan a single target or multiple hosts from a file.
- **Automation-Friendly Output**: Outputs results to structured directories with CSV files for easy parsing.
- **File Watching**: Automatically processes newly created service enumeration files for additional analysis.

---

## Features
- **ASCII Art Banner**: Customizable banner for a professional touch.
- **Quick UDP & Full TCP Scans**: Leverages Nmap to discover open ports.
- **Service Detection**: Identifies services and products running on open ports.
- **Protocol Modules**: Includes pre-built enumeration modules for:
  - HTTP
  - FTP
  - SSH
  - Telnet
  - SMB
  - SNMP
  - MySQL
  - RDP
  - SMTP
    
- **File Monitoring**: Continuously monitors output directories for updates to CSV files and processes them.
- **Customizable Input**: Supports custom wordlists, usernames, and passwords for more targeted testing.

---

## Dependencies
Ensure the following are installed:
- **Python**: >= 3.6
- **Install Modules:**

    pip3 install -r requirements.txt
  
  **Required modules include:**

      colorama

      pandas

      nmap

      watchdog

# Usage
## Target a single host
python3 questrecon.py -t <target_IP>

## Target multiple hosts from a host file
python3 questrecon.py -H <path_to_host_file>

## Specify output directory (if no arg provided, ~/results will be created in the current working directory)
python3 questrecon.py -t <target_IP> -o <path_to_output_directory)

## Customize directory wordlist, username, or password (username and password can be either wordlists or strings)
python3 questrecon.py -t <target_IP> -u <username_string_or_directory_path> -p <password_string_or_directory_path> 

## Default values
_Wordlist_: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

_Usernames_: /usr/share/seclists/Usernames/top-usernames-shortlist.txt

_Passwords_: /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt


# Disclaimer
QuestRecon is intended for authorized security testing and research purposes only. Unauthorized use may violate laws and agreements, and contributors to QuestRecon accept no responsibility for damage caused by misuse.


