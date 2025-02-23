#!/bin/python3

# Python script to check one certificate and used by the Check-Certificates script

import ssl
import socket
import json
import time
import argparse
import datetime

# Check if cryptography is available
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Connect to server and fetch SSL certificate
def fetch_certificate(domain, port):
    if CRYPTO_AVAILABLE:
        try:
            pem_cert = ssl.get_server_certificate((domain, port))
            cert = x509.load_pem_x509_certificate(pem_cert.encode(), default_backend())
            return cert, None
        except Exception as e:
            return None, str(e)
    else:
        # Fallback using built-in ssl module
        context = ssl._create_unverified_context()  # Allow fetching expired certs
        try:
            with socket.create_connection((domain, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert(), None
        except Exception as e:
            return None, str(e)

# Extract certificate details
def extract_certificate_details(cert):
    if CRYPTO_AVAILABLE:
        try:
            # Extract subject
            subject = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            subject_name = subject[0].value if subject else "Unknown"

            # Extract SAN (Subject Alternative Name)
            try:
                san_extension = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san = san_extension.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                san = []

            # Extract issuer
            issuer = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            issuer_name = issuer[0].value if issuer else "Unknown"

            # Extract validity period
            valid_from = cert.not_valid_before_utc
            valid_until = cert.not_valid_after_utc

            # Generate thumbprint
            thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()

            return {
                "subject": subject_name,
                "subject_alt_names": san,
                "issuer": issuer_name,
                "valid_from": valid_from.isoformat(),
                "valid_until": valid_until.isoformat(),
                "thumbprint": thumbprint
            }
        except Exception as e:
            return {"error": f"Failed to extract certificate details (cryptography): {str(e)}"}
    else:
        # Fallback using ssl module
        try:
            subject = dict(x[0] for x in cert.get('subject', []))
            san = cert.get('subjectAltName', [])
            issuer = dict(x[0] for x in cert.get('issuer', []))

            not_before_str = cert.get('notBefore')
            not_after_str = cert.get('notAfter')

            not_before = (
                datetime.datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                if not_before_str else None
            )
            not_after = (
                datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
                if not_after_str else None
            )

            fingerprint = cert.get('serialNumber', 'Unknown')

            return {
                "subject": subject.get('commonName', 'Unknown'),
                "subject_alt_names": [name[1] for name in san],
                "issuer": issuer.get('commonName', 'Unknown'),
                "valid_from": not_before.isoformat() if not_before else 'Unknown',
                "valid_until": not_after.isoformat() if not_after else 'Unknown',
                "thumbprint": fingerprint
            }
        except Exception as e:
            return {"error": f"Failed to extract certificate details (ssl): {str(e)}"}

# Perform checks on certificate
def evaluate_certificate(cert_details, domain):
    errors = []
    warnings = []
    now = datetime.datetime.now(datetime.UTC)

    # Check FQDN against subject and SAN
    if domain != cert_details['subject'] and domain not in cert_details['subject_alt_names']:
        errors.append("FQDN not found in Subject Name or Subject Alternative Name.")

    # Check expiry
    try:
        valid_until = datetime.datetime.fromisoformat(cert_details['valid_until'])
        
        if now > valid_until:
            errors.append("Certificate has expired.")
        elif valid_until - now <= datetime.timedelta(days=7):
            warnings.append("Certificate is within a week of expiring.")
    except Exception as e:
        errors.append("Certificate Valid Until invalid or missing")

    # Check expiry
    try:
        valid_from = datetime.datetime.fromisoformat(cert_details['valid_from'])
        
        if valid_from > now:
            errors.append("Certificate is not effective yet.")
    except Exception as e:
        errors.append("Certificate Valid From invalid or missing")

    # Check for self-signed certificates
    if cert_details['subject'] == cert_details['issuer']:
        warnings.append("Certificate is self-signed.")

    return errors, warnings

# Main check function
def run_certificate_check(domain, port):
    start_time = time.time()
    cert, fetch_error = fetch_certificate(domain, port)

    if fetch_error:
        result = {
            "status": "error",
            "errors": [fetch_error],
            "warnings": [],
            "message": "Failed to retrieve certificate.",
            "performance": f"{(time.time() - start_time):.3f} seconds"
        }
        return json.dumps(result, indent=4)

    cert_details = extract_certificate_details(cert)

    if "error" in cert_details:
        result = {
            "status": "error",
            "errors": [cert_details["error"]],
            "warnings": [],
            "message": "Failed to extract certificate details.",
            "performance": f"{(time.time() - start_time):.3f} seconds"
        }
        return json.dumps(result, indent=4)

    errors, warnings = evaluate_certificate(cert_details, domain)

    result = {
        "status": "success" if not errors else "error",
        "errors": errors,
        "warnings": warnings,
        "message": "Certificate is valid." if not errors else "Certificate has issues.",
        "details": cert_details,
        "performance": f"{(time.time() - start_time):.3f} seconds"
    }

    return json.dumps(result, indent=4)

# Only run this block if executed directly, not when imported
if __name__ == "__main__":
    import argparse

    def parse_arguments():
        parser = argparse.ArgumentParser(description="Check SSL certificate details for a given domain.")
        parser.add_argument("-d", "--domain", required=True, help="Fully Qualified Domain Name (FQDN) of the server.")
        parser.add_argument("-p", "--port", type=int, default=443, help="Port number (default is 443).")
        return parser.parse_args()
        
    args = parse_arguments()
    output = run_certificate_check(args.domain, args.port)
    print(output)