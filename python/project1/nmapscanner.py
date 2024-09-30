#!/usr/bin/env python3

"""
    Labb 1:

Kan göras enskilt eller i grupp. Om ni jobbar i grupp, använd gärna git(github) för att jobba tillsammans.

Installera python-nmap via PIP.

Skriv ett eget verktyg som använder nmap för att skanna ip adresser.

Krav:

    Möjlighet att spara resultatet av skanningen till fil (.txt)
    Använd input/fil för att bestämma vilka ip-adresser som ska skannas
    Programmet ska ha en meny där användaren kan välja vad som ska göras.


Använd din fantasi för att skapa fler funktioner i verktyget.

Skicka in skriptet, antingen via Github länk eller som en .py fil.
Notera gärna om scriptet har testats på Windows, Linux eller Mac.
Notera om du arbetat i grupp - Skriv alla namn på deltagare i gruppen
"""


from os import path
import nmap


NMAP_SCAN_TYPE = {
    "-sS": "Use SYN scan (stealth)",
    "-sT": "Use TCP connect scan",
    "-sU": "Use UDP scan"
}

NMAP_SCAN_FLAG = {
    "-O": "Enable OS detection",
    "-Pn": "Disable ping scan"
}


def selectScanType() -> str:
    print("Scan type:")
    for i, scan_type in enumerate(NMAP_SCAN_TYPE):
        print(f"     {i}) {scan_type}: {NMAP_SCAN_TYPE[scan_type]}")
    
    while True:
        try:
            n_option = int(input(f"Option 0-{len(NMAP_SCAN_TYPE) - 1}: "))
            
            if 0 <= n_option < len(NMAP_SCAN_TYPE):
                option = list(NMAP_SCAN_TYPE.keys())[n_option]
                return option
            else:
                print("Invalid option, try again.")
        except ValueError:
            print("Please enter a valid number.")


def getScanOptions():
    print("Scan options:")
    for i, scan_flag in enumerate(NMAP_SCAN_FLAG):
        print(f"     {i}) {scan_flag}: {NMAP_SCAN_FLAG[scan_flag]}")
    flags = []
    option = "."

    while option != "":
        option = input(f"Flag (enter to finish): ")
        if option in NMAP_SCAN_FLAG.keys():
            flags.append(option)
        else:
            print("Invalid flag.")

def nmapScan():
    nm = nmap.PortScanner()
    
    write_file = yesNo("Write to file?")
    if write_file: 
        output_filename = input("Filename: ")
    if path.exists(output_filename):
        if not askOverwrite(output_filename):
            return
    
    load_from_file = yesNo("Load IPs from file?")
    if load_from_file:
        while True:
            ips_filename = input("Filename: ")
            if path.exists(ips_filename):
                break
            else:
                print("File not found.")
        ips = getAdresssesFromFile(ips_filename)
    
    ports = getPortRange()
    scan_type = selectScanType()
    flags = getScanOptions()
    
    if load_from_file:
        for ip in ips:
            nm.scan(ip, ports, arguments=f"{scan_type} {flags}")
    else:
        ip = input("IP: ")
        nm.scan(ip, ports, arguments=f"{scan_type} {flags}")
    output_file = open(output_filename, "w")
    if write_file: output_file.write(ip)
    
    file_output = ""
    #credd chatgpt för denna del
    for proto in nm[ip].all_protocols():
        ports = nm[ip][proto].keys()
        
        for port in ports:
            state = nm[ip][proto][port]['state']
            name = nm[ip][proto][port]['name']
            product = nm[ip][proto][port].get('product', 'Unknown')
            version = nm[ip][proto][port].get('version', 'Unknown')
            
            if state == 'open':
                output = f"Port: {port}, Service: {name}, Product: {product}, Version: {version}"
                file_output += output
                
    if write_file:
        writeResultToFile(file_output)
        
        
def getPortRange() -> str:
    print("Enter port: 21")
    print("a range of ports: 1-1024")
    print("or a list of ports, separated by space: 21 80 443")
    ports = input(": ")
    
    return ports
    
    

def getAdresssesFromFile(file) -> list:
    ips = []
    
    with open(file, "r") as ip_file:
        
        for ip in ip_file:
            ips.append(ip.rstrip())

    return ips



def writeResultToFile(filename, content):
    if path.exists(filename):
        askOverwrite(filename)
        
    with open(filename, "w") as file:
        file.write(content)


def askOverwrite(filename):
    if not yesNo(f"{filename} already exists. Overwrite?"):
        return False
    return True


def yesNo(prompt) -> bool:
    
    while True:
        user_input = input(f"{prompt} (y/n): ").strip().lower()
        
        if user_input and user_input[0] in ("y", "n"):
            return user_input[0] == "y"
        
        print("Invalid input.")


nmapScan()
