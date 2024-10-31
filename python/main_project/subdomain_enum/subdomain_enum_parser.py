#!/usr/bin/python3
import argparse
from . import subdomain_enum_main
import sys
from rich.console import Console

console = Console()

def parse_args():
    parser = argparse.ArgumentParser(
        description="Subdomain Enumeration Tool",
        epilog="by Aldin Smajlovic"
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Use the GUI for subdomain enumeration"
    )
    parser.add_argument(
        "-d", "--domain",
        type=str,
        help="The target domain for enumeration (e.g., example.com)"
    )
    parser.add_argument(
        "-w", "--wordlist",
        type=str,
        help="File containing subdomains to test against the domain"
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        help="Output file to save subdomains from DNSDumpster and test results"
    )
    parser.add_argument(
        "--dns-dumpster",
        action="store_true",
        help="Fetch subdomains from DNSDumpster for the specified domain"
    )
    parser.add_argument(
        "--http",
        action="store_true",
        help="Use HTTP instead of HTTPS for subdomain testing"
    )
    return parser.parse_args()

def fetch_dnsdumpster_subdomains(domain: str) -> list[str]:
    console.print(f"Fetching subdomains from DNSDumpster for {domain}...")
    return subdomain_enum_main.get_dnsdumpster_subdomains(domain)

def output_subdomains(subdomains: list[str], output: str):
    if output:
        subdomain_enum_main.write_to_file(output, "\n".join(subdomains) + "\n")
        console.print(f"Subdomains saved to [green]{output}[/green]")
    else:
        print("\n".join(subdomains))

def test_subdomains(domain: str, subdomains: list[str], use_http: bool) -> list[tuple[str, int]]:
    url_list = subdomain_enum_main.generate_url_list(domain, subdomains, use_http=use_http)
    return subdomain_enum_main.make_threaded_requests(url_list)

def output_test_results(results: list[tuple[str, int]], output: str):
    formatted_results = "\n".join(f"{status}: {url}" for url, status in results if status != 0)
    if output:
        subdomain_enum_main.write_to_file(output, formatted_results, mode="a")
        console.print(f"Test results appended to [green]{output}[/green]")
    else:
        print(formatted_results)

def main():
    args = parse_args()
    console.print(f"[bold]{subdomain_enum_main.BANNER}[/bold]")

    if not args.gui and not args.domain:
        console.print("[bold red]Error:[/bold red] The --domain argument is required when not using --gui.")
        sys.exit(1)

    all_subdomains = []
    if args.gui:
        subdomain_enum_main.main()
    if args.dns_dumpster and args.domain:
        dnsdumpster_subdomains = fetch_dnsdumpster_subdomains(args.domain)
        
        if args.output:
            all_subdomains.extend(dnsdumpster_subdomains)
            output_subdomains(dnsdumpster_subdomains, args.output)
        else:
            output_subdomains(dnsdumpster_subdomains, None)

    if args.wordlist and args.domain:
        if not subdomain_enum_main.is_valid_file(args.wordlist):
            console.print(f"[bold red]Error:[/bold red] Wordlist file '{args.wordlist}' does not exist.")
            sys.exit(1)

        console.print(f"Testing subdomains from wordlist '{args.wordlist}' for {args.domain}...")
        wordlist_subdomains = subdomain_enum_main.get_wordlist_subdomains(args.wordlist)
        all_subdomains.extend(wordlist_subdomains)

    if all_subdomains and args.domain:
        results = test_subdomains(args.domain, all_subdomains, use_http=args.http)
        output_test_results(results, args.output)

if __name__ == "__main__":
    main()
