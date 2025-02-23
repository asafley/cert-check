#!/bin/python3

# Python script to check multiple certificates with an option to print report to stdin, to CSV file, or email

import os
import csv
import json
import argparse
import smtplib
import time
import configparser
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from concurrent.futures import ThreadPoolExecutor, as_completed

from Check_Certificate import run_certificate_check

# Parse command-line arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Check multiple SSL certificates and send email reports.")
    parser.add_argument("-i", "--input", required=True, help="Path to input JSON or CSV file.")
    parser.add_argument("-o", "--output", required=False, help="Optional: Path to output CSV report.")
    parser.add_argument("-e", "--email", help="Recipient email address for sending the report.")
    parser.add_argument("--config", default="config.ini", help="Path to the configuration INI file.")
    parser.add_argument("-t", "--threads", type=int, default=0, help="Number of thread workers for checking certificates.")
    
    return parser.parse_args()

# Load from config file
def load_config(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)

    email_config = {
        "from_address": config.get('EMAIL', 'from_address'),
        "from_name": config.get('EMAIL', 'from_name'),
        "reply_to_address": config.get('EMAIL', 'reply_to_address'),
        "reply_to_name": config.get('EMAIL', 'reply_to_name'),
        "smtp_host": config.get('EMAIL', 'smtp_host'),
        "smtp_port": config.getint('EMAIL', 'smtp_port'),
        "use_tls": config.getboolean('EMAIL', 'use_tls'),
        "smtp_username": config.get('EMAIL', 'smtp_username'),
        "smtp_password": config.get('EMAIL', 'smtp_password'),
    }

    thread_config = {
        "max_threads": config.getint('THREADS', 'max_threads', fallback=os.cpu_count())
    }

    return email_config, thread_config

# Read input file (JSON or CSV)
def read_input_file(filepath):
    domains = []
    if filepath.endswith('.json'):
        with open(filepath, 'r') as file:
            domains = json.load(file)
    elif filepath.endswith('.csv'):
        with open(filepath, 'r') as file:
            reader = csv.DictReader(file)
            domains = [row for row in reader]
    else:
        raise ValueError("Unsupported file format. Use JSON or CSV.")
    return domains

def truncate_with_ellipsis(text, max_length):
    """
    Truncate text with ellipsis if it exceeds the maximum length.
    """
    return (text[:max_length - 3] + '...') if len(text) > max_length else text

# Print results to console in a readable format
def print_results_to_console(results):
    # Define column widths
    col_widths = {
        "Name": 16,
        "Domain": 32,
        "Port": 8,
        "Status": 8,
        "Valid Until": 32,
        "Issuer": 16,
        "Subject": 32
    }

    # Print header
    header = f"{'Name':<{col_widths['Name']}} {'Domain':<{col_widths['Domain']}} {'Port':<{col_widths['Port']}} {'Status':<{col_widths['Status']}} {'Valid Until':<{col_widths['Valid Until']}} {'Issuer':<{col_widths['Issuer']}} {'Subject'}"
    print("\nSSL Certificate Check Results:\n")
    print(header)
    print("-" * len(header))


    # Print each row with truncated values
    for result in results:
        print(f"{truncate_with_ellipsis(result['Name'], col_widths['Name']):<{col_widths['Name']}} "
              f"{truncate_with_ellipsis(result['Domain'], col_widths['Domain']):<{col_widths['Domain']}} "
              f"{str(result['Port']):<{col_widths['Port']}} "
              f"{truncate_with_ellipsis(result['Status'], col_widths['Status']):<{col_widths['Status']}} "
              f"{truncate_with_ellipsis(result['Valid Until'], col_widths['Valid Until']):<{col_widths['Valid Until']}} "
              f"{truncate_with_ellipsis(result['Issuer'], col_widths['Issuer']):<{col_widths['Issuer']}} "
              f"{truncate_with_ellipsis(result['Subject'], col_widths['Subject'])}")

# Write results to a CSV file
def write_results_to_csv(results, output_file):
    with open(output_file, 'w', newline='') as file:
        fieldnames = ["Name", "Domain", "Port", "Status", "Errors", "Warnings", "Valid Until", "Issuer", "Subject"]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow(result)

# Send email with results table
def send_email(recipient, results, email_config):
    sender = email_config["from_address"]
    from_name = email_config.get("from_name", sender)
    reply_to_address = email_config.get("reply_to_address", sender)
    reply_to_name = email_config.get("reply_to_name", from_name)
    smtp_host = email_config["smtp_host"]
    smtp_port = email_config["smtp_port"]
    smtp_username = email_config.get("smtp_username")
    smtp_password = email_config.get("smtp_password")
    use_tls = email_config.get("use_tls", True)

    # Define colors for each status
    status_colors = {
        "error": "#f8d7da",   # Light red
        "warning": "#fff3cd", # Light yellow
        "success": "#d4edda"  # Light green
    }

    subject = "SSL Certificate Check Report"

    # Create HTML content
    html = """
    <html><body>
    <h2>SSL Certificate Check Results</h2>
    <table border='1' cellpadding='5' cellspacing='0'>
    <tr>
        <th>Name</th><th>Domain</th><th>Port</th><th>Status</th><th>Errors</th><th>Warnings</th><th>Valid Until</th><th>Issuer</th><th>Subject</th>
    </tr>
    """

    # Generate table rows with color-coded backgrounds
    for result in results:
        status = result['Status'].lower()
        bg_color = status_colors.get(status, "#ffffff")  # Default to white if status is unknown

        html += f"<tr style='background-color: {bg_color};'>"
        html += f"<td>{result['Name']}</td>"
        html += f"<td>{result['Domain']}</td>"
        html += f"<td>{result['Port']}</td>"
        html += f"<td>{result['Status']}</td>"
        html += f"<td>{', '.join(result['Errors']) if result['Errors'] else 'None'}</td>"
        html += f"<td>{', '.join(result['Warnings']) if result['Warnings'] else 'None'}</td>"
        html += f"<td>{result['Valid Until']}</td>"
        html += f"<td>{result['Issuer']}</td>"
        html += f"<td>{result['Subject']}</td>"
        html += "</tr>"

    html += "</table></body></html>"

    # Create email message
    message = MIMEMultipart("alternative")
    message["From"] = f"{from_name} <{sender}>"
    message["To"] = recipient
    message["Subject"] = subject
    message.add_header("Reply-To", f"{reply_to_name} <{reply_to_address}>")
    message.attach(MIMEText(html, "html"))

    # Send email
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        if use_tls:
            server.starttls()
        if smtp_username and smtp_password:
            server.login(smtp_username, smtp_password)
        server.send_message(message)

    print(f"Report sent to {recipient}")

# Function to run a certificate check for multithreading
def check_certificate_multithread(entry):
    name = entry.get('name')
    domain = entry.get('domain')
    port = int(entry.get('port', 443))
    cert_check_result = json.loads(run_certificate_check(domain, port))

    details = cert_check_result.get('details', {})
    return {
        "Name": name,
        "Domain": domain,
        "Port": port,
        "Status": cert_check_result.get('status'),
        "Errors": cert_check_result.get('errors', []),
        "Warnings": cert_check_result.get('warnings', []),
        "Valid Until": details.get('valid_until', 'Unknown'),
        "Issuer": details.get('issuer', 'Unknown'),
        "Subject": details.get('subject', 'Unknown')
    }

# Main function
def main():
    start_time = time.time()
    args = parse_arguments()
    domains = read_input_file(args.input)

    # Load configurations from INI file
    email_config, thread_config = load_config(args.config)

    results = []

    # Use threads from config unless overridden
    max_threads = args.threads if args.threads > 0 else thread_config['max_threads']
    print(f"Using {max_threads} thread(s) for parallel processing...")

    # Run SSL checks in parallel
    with ThreadPoolExecutor(max_threads) as executor:
        future_to_domain = {executor.submit(check_certificate_multithread, entry): entry for entry in domains}
        for future in as_completed(future_to_domain):
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                entry = future_to_domain[future]
                print(f"Error processing {entry.get('domain')}:{entry.get('port')} - {e}")

    # Sort results by expiration date
    results.sort(key=lambda x: x['Valid Until'] if x['Valid Until'] != 'Unknown' else '9999-12-31T00:00:00')

    # Output results
    if args.output:
        write_results_to_csv(results, args.output)
        print(f"Results written to {args.output}")
    else:
        print_results_to_console(results)

    # Send email if email address is provided
    if args.email:
        send_email(args.email, results, email_config)

    print(f"Completed in {(time.time() - start_time):.3f} seconds")

if __name__ == "__main__":
    main()