#!/usr/bin/python3
# Testad med Python 3.12.5 och python-nmap 0.7.1 på Windows 11

from os import path
import nmap
import re

def printBanner():
    banner = """
██╗   ██╗██╗███╗   ██╗███████╗
██║   ██║██║████╗  ██║██╔════╝
██║   ██║██║██╔██╗ ██║███████╗
╚██╗ ██╔╝██║██║╚██╗██║╚════██║
 ╚████╔╝ ██║██║ ╚████║███████║
  ╚═══╝  ╚═╝╚═╝  ╚═══╝╚══════╝
 Very Inferior Network Scanner
"""
    print(banner)

NMAP_SCAN_TYPE = {
    "-sS": "Use SYN scan (stealth)",
    "-sT": "Use TCP connect scan",
    "-sU": "Use UDP scan"
}

NMAP_SCAN_FLAG = {
    "-O": "Enable OS detection",
    "-Pn": "Disable ping scan"
}

def is_valid_ip(ip: str) -> bool:
    pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(pattern, ip):
        return all(0 <= int(part) <= 255 for part in ip.split('.'))
    return False

def is_valid_ports(ports: str) -> bool:
    pattern = r"^(\d+(-\d+)?)( \d+(-\d+)?)*$"
    return bool(re.match(pattern, ports))

def selectScanType() -> str:
    print("\nSelect scan type:\n")
    for i, scan_type in enumerate(NMAP_SCAN_TYPE):
        print(f"     {i}) {scan_type}: {NMAP_SCAN_TYPE[scan_type]}")
    
    while True:
        try:
            print()
            n_option = int(input(f"Option 0-{len(NMAP_SCAN_TYPE) - 1}: "))
            if 0 <= n_option < len(NMAP_SCAN_TYPE):
                return list(NMAP_SCAN_TYPE.keys())[n_option]
            else:
                print("Invalid option, try again.")
        except ValueError:
            print("Please enter a valid number.")

def getScanOptions() -> str:
    print("\nSelect scan options:\n")
    for i, scan_flag in enumerate(NMAP_SCAN_FLAG):
        print(f"     {i}) {scan_flag}: {NMAP_SCAN_FLAG[scan_flag]}")
    
    flags = []
    while True:
        print()
        option = input("Flag (enter to finish): ").strip()
        if option == "":
            break
        if option in NMAP_SCAN_FLAG:
            flags.append(option)
        else:
            print("Invalid flag.")
    return " ".join(flags)

def nmapScan():
    nm = nmap.PortScanner()
    
    print("\n-------------------------")
    write_file = yesNo("Write to file?")
    if write_file: 
        print()
        output_filename = input("Filename: ")
        if path.exists(output_filename):
            if not yesNo("File exists. Append to file?"):
                if not askOverwrite(output_filename):
                    return
    
    print("\n-------------------------")
    load_from_file = yesNo("Load IPs from file?")
    if load_from_file:
        print()
        ips_filename = input("Filename: ")
        while not path.exists(ips_filename):
            print("File not found.")
            ips_filename = input("Filename: ")
        ips = getAddressesFromFile(ips_filename)
    else:
        print()
        ips = [input("Enter IP: ").strip()]
        while not is_valid_ip(ips[0]):
            print("Invalid IP address.")
            ips = [input("Enter valid IP: ").strip()]

    print("\n-------------------------")
    ports = getPortRange()
    scan_type = selectScanType()
    flags = getScanOptions()
    
    file_output = ""
    
    for ip in ips:
        print(f"\nScanning {ip}...\n")
        try:
            nm.scan(ip, ports, arguments=f"{scan_type} {flags}")
            if nm[ip].all_protocols():
                result = f"\n{'-'*40}\nResults for IP: {ip}\n{'-'*40}\n"
                for proto in nm[ip].all_protocols():
                    ports = nm[ip][proto].keys()
                    for port in ports:
                        state = nm[ip][proto][port]['state']
                        name = nm[ip][proto][port].get('name', 'Unknown')
                        product = nm[ip][proto][port].get('product', 'Unknown')
                        version = nm[ip][proto][port].get('version', 'Unknown')
                        
                        if state == 'open':
                            result += f"Port: {port}, Service: {name}, Product: {product}, Version: {version}\n"
                print(result)
                file_output += result
            else:
                print(f"No open protocols found for {ip}")
        except Exception as e:
            print(f"Error scanning {ip}: {e}")

    if write_file:
        writeResultToFile(output_filename, file_output)


def getPortRange() -> str:
    print("\nEnter a single port: 21")
    print("or a range of ports: 1-1024")
    print("or a list of ports, separated by spaces: 21 80 443\n")
    while True:
        ports = input(": ")
        if is_valid_ports(ports):
            return ports
        print("Invalid port format. Please try again.")

def getAddressesFromFile(file) -> list:
    ips = []
    with open(file, "r") as ip_file:
        ips = [ip.strip() for ip in ip_file if is_valid_ip(ip.strip())]
    return ips

def writeResultToFile(filename, content):
    with open(filename, "a") as file:
        file.write(content)

def askOverwrite(filename) -> bool:
    return yesNo(f"{filename} already exists. Overwrite?")

def yesNo(prompt) -> bool:
    while True:
        print()
        user_input = input(f"{prompt} (y/n): ").strip().lower()
        if user_input and user_input[0] in ("y", "n"):
            return user_input[0] == "y"
        print("Invalid input.")

if __name__ == "__main__":
    printBanner()
    nmapScan()
