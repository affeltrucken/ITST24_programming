# Subdomain Enumeration Tool

This Subdomain Enumeration Tool is a Python-based application designed for efficient subdomain discovery and validation. With support for both CLI and GUI interfaces, the tool provides multiple features, such as fetching subdomains from DNSDumpster, testing subdomains from custom wordlists, and saving results to an output file.

## Features

* Fetch Subdomains from DNSDumpster for specified domains.
* Wordlist-Based testing to discover additional subdomains.
* CLI and GUI Support for ease of use.

## Prerequisites

- **Tested with Python 3.12.5**
- **Required Libraries**:
    - argparse
    - rich

You can install the required libraries using pip:

```bash
pip install argparse rich
```

##Usage

Subdomain-enum provides both a command-line interface (CLI) and a graphical user interface (GUI).

### Command-Line Interface (CLI)

You can use the CLI to generate a subdomain wordlist from dnsdumpster, or scan a domain using a provided wordlist.

To start the CLI, run:

```bash
python subdomain_enum.py [options]
```

Or, use the GUI with:

```bash
python subdomain_enum.py -i
```

# License

This project is licensed under the MIT License.

Contributions are welcome! Feel free to open issues or submit pull requests.
Acknowledgments

    DNSDumpster for the public API used in subdomain enumeration.
    Rich library for providing console formatting.