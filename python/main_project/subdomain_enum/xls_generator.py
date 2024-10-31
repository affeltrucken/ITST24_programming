from openpyxl import Workbook
from datetime import datetime

def generate_spreadsheet(domain: str, subdomain_data: list[tuple[str, int]]) -> str:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Subdomain Scan Results"

    headers = ["Subdomain", "Status Code", "Timestamp"]
    sheet.append(headers)
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for url, status_code in subdomain_data:
        sheet.append([url, status_code, scan_time])

    filename = f"{domain.replace('.', '_')}_subdomain_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    workbook.save(filename)
    print(f"Spreadsheet saved as: {filename}")
    return filename