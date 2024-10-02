#!/usr/bin/python3
import signal
import argparse
import textwrap
import threading
import requests as rq
from bs4 import BeautifulSoup
from prettytable import PrettyTable
from alive_progress import alive_bar
from urllib3.exceptions import InsecureRequestWarning
from zapv2 import ZAPv2
from fpdf import FPDF  # For generating PDF reports
import time
import os
import datetime

# Exception 
rq.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# ZAP API and URL configuration
API_KEY = 'a70p8l1f5i04pgk6ujhko76dov'  # ZAP API key
ZAP_URL = 'http://localhost:8080'  # ZAP instance URL
zap = ZAPv2(apikey=API_KEY, proxies={'http': ZAP_URL, 'https': ZAP_URL})

# Base report directory for both live host and ZAP scan reports
BASE_REPORT_DIR = '/home/mavindu/Desktop/test/reports/'

# Function to display ASCII banner
def display_banner():
    print("---------------------------------------------------------------------------------------------------------------")
    print("------------ | Automate the scan for checking live hosts and vulnerabilities.| --------------")
    print("---------------------------------------------------------------------------------------------------------------")
    print(" /  __ \\     | |             /  ___|          ")
    print("| /  \\/_   _| |__   ___ _ __\\ --.  ___  ___ ")
    print("| |   | | | | '_ \\ / _ \\ '__|--. \\/ _ \\/ __|")
    print("| \\__/\\ |_| | |_) |  __/ |  /\\__/ /  __/ (__ ")
    print(" \\____/\\__, |_.__/ \\___|_|  \\____/ \\___|\\___|")
    print("        __/ |                                ")
    print("       |___/                                 ")
    print("                                      V 0.1")
    print("        ---------------------|by Mavindu_Wijesekara")
    print("-------------------------------------------------------------")

# Get arguments for the live host scan
parser = argparse.ArgumentParser(
    prog='CyberSec.py',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=textwrap.dedent('''\
-------------------------------------------------------------
------------ | Mass scan for checking live hosts | --------------
-------------------------------------------------------------'''),
    usage='python3 %(prog)s -u [URLList] -to [Timeout]',
    epilog='---------------- Script from YourWebsite.com ----------------')

parser._action_groups.pop()
required = parser.add_argument_group('[!] Required arguments')
required.add_argument('-u', '--urllist', metavar='', required=True, help='Target URLs file')
required.add_argument('-to', '--timeout', metavar='', type=int, help='Set timeout (Default is 3)')
args = parser.parse_args()

# Style settings for console output
class style():
    HEADER = '\033[95m'
    BLINK = '\33[5m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BOLD  = '\033[1m'
    RESET = '\033[0m'
    RED = '\033[31m'

# Get URL list from the provided file
with open(args.urllist) as f:
    url_list = [x.rstrip() for x in f]

# Set Timeout
t_out = args.timeout if args.timeout is not None else 3

# Table settings for live host result
table = PrettyTable()
table.title = "-----------| CyberSec v0.1 :: by Mavindu_Wijesekara |-----------"
table.field_names = ['URL', 'Status', 'Title']
table.align['URL'] = 'l'
table.align['Title'] = 'l'
table.sortby = 'Status'

# To hold the live URLs for ZAP scanning later
live_urls = []

def quit(signal, frame):
    print (style.RED+"----------| Program stopped due to CTRL + C "+style.RESET)
    print("Bye!")
    raise SystemExit

# Add scheme if no scheme is present
def add_default_scheme(url):
    if not url.startswith(('http://', 'https://')):
        return 'http://' + url
    return url

# Function to generate a new session in ZAP
def start_new_session():
    session_name = f"session_{int(time.time())}"
    print(f"New session started: {session_name}")
    zap.core.new_session(name=session_name, overwrite=True)

# Function to configure aggressive scan in ZAP
def configure_aggressive_scan():
    print("Configuring ZAP for aggressive scanning...")
    zap.ascan.set_option_attack_policy('Default Policy')  # Set the scan policy
    zap.ascan.set_option_thread_per_host(10)  # Increase the number of concurrent scans
    zap.ascan.set_option_delay_in_ms(0)  # No delay between scan requests

# Function to scan the URL using ZAP and generate a report
def zap_scan(url, scan_report_dir):
    configure_aggressive_scan()  # Configure ZAP for aggressive scan
    print(f"Starting ZAP scan for {url}")
    
    # Start spider scan
    print(f"Starting spider scan on: {url}")
    scan_id = zap.spider.scan(url)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"Spider scan progress: {zap.spider.status(scan_id)}%")
        time.sleep(5)
    print("Spider scan completed")

    # Start active scan (deep scan)
    print(f"Starting active scan on: {url}")
    scan_id = zap.ascan.scan(url, recurse=True, inscopeonly=False)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"Active scan progress: {zap.ascan.status(scan_id)}%")
        time.sleep(10)
    print("Active scan completed")

    # Generate the ZAP scan report in HTML
    report_filename = f"{url.replace('https://', '').replace('http://', '').replace('/', '_')}_report.html"
    report_path = os.path.join(scan_report_dir, report_filename)
    with open(report_path, 'w') as report_file:
        report_file.write(zap.core.htmlreport())
    print(f"Report saved to: {report_path}")

# Function to check live URLs and generate the live hosts report
def check_live_hosts(report_dir):
    with alive_bar(len(url_list), bar='blocks') as bar:
        for url in url_list:
            try:
                url = add_default_scheme(url)
                req = rq.get(url, timeout=t_out, verify=False)
                soup = BeautifulSoup(req.text, 'html.parser')
                if soup.title is not None:
                    table.add_row([url, req.status_code, soup.title.text])
                else:
                    table.add_row([url, req.status_code, 'Title Not Found'])

                # If URL is live, add it to live_urls list
                if req.status_code == 200:
                    live_urls.append(url)

                bar()

            except rq.exceptions.ConnectionError:
                print(style.RED+"[!] Error Connecting to: ", url+style.RESET)
            except rq.exceptions.Timeout:
                print(style.YELLOW+"[!] Timeout Error for: ", url+style.RESET)
            except rq.exceptions.RequestException as err:
                print(style.RED+"[!] Error: ", str(err)+style.RESET)
                raise SystemExit

    # Save live host results to HTML and PDF
    live_host_report_html = os.path.join(report_dir, "live_host_report.html")
    live_host_report_pdf = os.path.join(report_dir, "live_host_report.pdf")

    # HTML report
    with open(live_host_report_html, 'w') as report_file:
        report_file.write(table.get_html_string())
    print(f"\nLive hosts report saved to: {live_host_report_html}")

    # PDF report
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Live Hosts Report", ln=True, align='C')

    for row in table._rows:
        pdf.cell(200, 10, txt=str(row), ln=True)

    pdf.output(live_host_report_pdf)
    print(f"Live hosts report saved to: {live_host_report_pdf}")

    print("\n\n-----------| CyberSec v0.1 :: by Mavindu_Wijesekara |-----------")
    print(table)
    print("\n\n")

# Function to run ZAP scans on live URLs only
def run_zap_scans(report_dir):
    if not live_urls:
        print(style.YELLOW + "[!] No live URLs found, skipping ZAP scans." + style.RESET)
        return
    
    print(style.GREEN + "[+] Starting ZAP scans for live URLs..." + style.RESET)
    
    for url in live_urls:
        # Create a subfolder for each host's report
        host_report_dir = os.path.join(report_dir, url.replace('https://', '').replace('http://', '').replace('/', '_'))
        if not os.path.exists(host_report_dir):
            os.makedirs(host_report_dir)
        
        start_new_session()  # Start a new ZAP session for each live URL
        zap_scan(url, host_report_dir)

# Main
if __name__ == '__main__':
    signal.signal(signal.SIGINT, quit)

    # Display banner before running the scan
    display_banner()

    # Create a new report directory for each day, named with the date and time
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    daily_report_dir = os.path.join(BASE_REPORT_DIR, timestamp)
    if not os.path.exists(daily_report_dir):
        os.makedirs(daily_report_dir)

    # First, check for live hosts and generate live host report
    check_live_hosts(daily_report_dir)

    # Then, run ZAP scans for live hosts only and save reports in corresponding subfolders
    run_zap_scans(daily_report_dir)

