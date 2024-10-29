
from tools.general_tools import yes_no, write_to_file, input_file
from dnsdumpster.DNSDumpsterAPI import DNSDumpsterAPI
from rich.console import Console
from rich.prompt import Prompt

from pathlib import Path
import concurrent.futures

import sys
import requests

BANNER = """
  ___ ___  ___ 
 / __|   \\| __|
 \\__ \\ |) | _| 
 |___/___/|___| v1.0
 
 by Aldin Smajlovic"""
console = Console()

def read_file(filename: str) -> str:
    with open(filename, "r", encoding="utf-8") as file:
        return file.read()

def get_wordlist_subdomains(wordlist: str, n_of_lines: int = 500) -> list:
    with open(wordlist, 'r', encoding="utf-8") as file:
        wordlist_subdomains = [line.strip() for line in file]
    return wordlist_subdomains

def get_dnsdumpster_subdomains(basedomain: str, n_of_lines: int = 1000) -> list:
    results = DNSDumpsterAPI().search(basedomain)
    domains = []
    i = 0
    for host in results["dns_records"]["host"]:
        if i >= n_of_lines:
            break
        subdomain: str = host["domain"].removesuffix(f".{basedomain}")
        domains.append(subdomain)
    return domains

def make_request(url, timeout=60) -> tuple[str, int]:
    try:
        response = requests.get(url, timeout=timeout)
        return url, response.status_code
    except requests.RequestException:
        return url, 0

def generate_url_list(base_domain: str, subdomain_list: list[str], use_http=False) -> list:
    url_list = []
    for subdomain in subdomain_list:
        url_list.append(f"{'https' if not use_http else 'http'}://{subdomain}{"." if subdomain[-1] != "." else ""}{base_domain}")
    return url_list

def make_threaded_requests(urls: list[str]) -> list[tuple[str, int]]:
    responses = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_url = {executor.submit(make_request, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                responses.append(future.result())
            except Exception:
                responses.append((url, 0))
    return responses

def ask_save_output(prompt="Save output?") -> str:
    if yes_no(prompt):
        filename = input_file(ask_overwrite=True, file_exists_required=False)
        return filename
    else:
        return ""

def is_valid_file(filename: str) -> bool:
    return Path(filename).exists()

def download_file_from_url(url: str, filename: str = "") -> str:
    try:
        response = requests.get(url, allow_redirects=True, timeout=15)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"Error downloading file: {e}")
        return ""

    if not filename:
        filename = Prompt.ask("Enter a filename: ")

    with open(filename, "wb") as file:
        file.write(response.content)

    return filename

def remove_duplicates_from_list(subdomain_list: list) -> list:
    return list(set(subdomain_list))

def print_subdomains(responses: list[tuple[str, int]]) -> None:
    for url, status_code in responses:
        if status_code == 0:
            continue
        print(f"{status_code}: {url}")

def load_subdomains_from_file(subdomain_list: list[str], default="https://raw.githubusercontent.com/bugcrowd/subdomain-names/master/subdomains-top1million-5000.txt") -> list[str]:
    if yes_no("Download subdomain list?"):
        url = Prompt.ask("URL (default is subdomains-top1million-5000.txt): ") or default
        filename = download_file_from_url(url)
        subdomain_list.extend(line.strip() for line in filename.splitlines())
        return subdomain_list
    else:
        while True:
            filename = Prompt.ask("Filename: ")
            if Path(filename).exists() and filename != "":
                break
            print("File not found.")

    with open(filename) as file:
        subdomain_list.extend(line.strip() for line in file)

    return subdomain_list


def load_subdomains_from_dnsdumpster(domain: str, subdomains: list[str]) -> list[str]:
    dnsdumpster_subdomains = get_dnsdumpster_subdomains(domain)
    subdomains.extend(dnsdumpster_subdomains)
    return subdomains
    
def main_menu(domain: str, subdomains: list[str]) -> tuple[str, list[str]]:
    """Main menu for subdomain enum."""
    options = {
        "1": "Enter domain",
        "2": "Load subdomains from DNSDumpster",
        "3": "Load subdomains from file",
        "4": "Check subdomains for domain",
        "5": "Print subdomain list (first 100)"
    }

    console.print("\n[bold cyan]Main Menu[/bold cyan]\n")
    for key, value in options.items():
        console.print(f"[bold]{key}:[/bold] {value}")

    option = Prompt.ask("> ", choices=list(options.keys()), show_choices=True)
    domain, subdomains = handle_choice(option, domain, subdomains)
    return domain, subdomains

def input_domain() -> str:
    while True:
        # I dont validate domains because regex usually doesn't work for domains with .co.uk for example
        # https://stackoverflow.com/questions/201323/how-to-validate-an-input-url-in-python
        # Will implement later
        domain = input("Domain (example.org): ")
        if domain:
            return domain

def print_invalid_option_message() -> None:
    print("[bold red]Invalid option! Please try again.[/bold red]")

def handle_choice(option: str, domain: str, subdomain_list: list[str]) -> tuple[str, list[str]]:
    match option:
        case "1":
            domain = input_domain()
        case "2":
            subdomain_list_dnsdumpster = get_dnsdumpster_subdomains(domain)
            print(subdomain_list_dnsdumpster)
            filename = ask_save_output("Save output?")
            if filename:
                write_to_file(filename, data="", mode="w")
                for subdomain in subdomain_list_dnsdumpster:
                    write_to_file(filename, data=f"{subdomain}\n")
                console.print(f"Saved to [green]{filename}[/green]")
            subdomain_list.extend(subdomain_list_dnsdumpster)
            print(f"Added {len(subdomain_list_dnsdumpster)} subdomains to list.")
        case "3":
            subdomain_list_file: list[str] = []
            subdomain_list_file = load_subdomains_from_file(subdomain_list_file)
            subdomain_list.extend(subdomain_list_file)
            print(f"Added {len(subdomain_list_file)} subdomains to list.")
        case "4":
            url_list = generate_url_list(domain, subdomain_list, use_http=yes_no("Use HTTP?"))
            print(f"Testing {len(url_list)} subdomains...")
            request_list = make_threaded_requests(url_list)
            print_subdomains(request_list)
        case "5":
            print(subdomain_list[0:100])
        case "0":
            print("[bold red]Exiting...[/bold red]")
            sys.exit()
        case _:
            print_invalid_option_message()

    return domain, subdomain_list

def menu_loop(domain_name, subdomain_list) -> None:
    console.print(f"[bold]{BANNER}[/bold]")
    while True:
        domain_name, subdomain_list = main_menu(domain_name, subdomain_list)

def main() -> None:
    domain_name: str = ""
    subdomain_list: list[str] = []
    menu_loop(domain_name, subdomain_list)

if __name__ == "__main__":
    main()
