
# Advanced SQL Injection (SQLi) Scanner Tool

The Advanced SQL Injection Scanner is a sophisticated, Python-based tool crafted for security analysts and penetration testers. It automates the detection of SQL Injection vulnerabilities in web applications by sending varied SQLi payloads to specified URLs and analyzing the responses for signs of injectable parameters. This tool aids in uncovering potential vulnerabilities that could allow unauthorized manipulation or access to an application's underlying database.

## Key Features

- **Custom Payloads**: Ability to use a custom list of SQLi payloads, enhancing targeted testing based on specific application contexts or tester insights.
- **Request Timeouts**: Supports custom request timeouts to adapt to different network conditions and prevent potential target server overloads.
- **Verbosity Levels**: Offers multiple verbosity levels for output, from minimal to debug, providing flexible feedback suited to various use cases.
- **Multiple Testing Methods**: Capable of testing GET and POST parameters, alongside automatic form detection and testing within HTML content (requires BeautifulSoup4).
- **Comprehensive Vulnerability Detection**: Employs a wide range of payloads (error-based, boolean-based, time-based) to identify various forms of SQLi vulnerabilities.
- **Ease of Use**: Despite its depth, the tool is user-friendly, offering an intuitive command-line interface suitable for all user levels.

## Installation and Setup

1. **Install Python 3**: Ensure Python 3 is installed on your system. If not, download and install it from [python.org](https://python.org).

2. **Install Required Libraries**: Open a terminal or command prompt and install the necessary Python libraries by running:
    ```bash
    pip install requests beautifulsoup4
    ```

3. **Save the Script**: Copy the SQLi scanner script into a file named `SQLiAS.py` on your machine.

## Usage

Run the tool from the command line, adjusting the command based on your testing needs.

### Basic Command Structure

```bash
python SQLiAS.py <URL> [OPTIONS]
```

### Options

- `--payloads FILE`: Specify a file with custom SQLi payloads. Replace `FILE` with your file path.
- `--timeout SECONDS`: Set a custom timeout for requests in seconds. Replace `SECONDS` with your desired timeout.
- `--verbosity LEVEL`: Adjust the verbosity level of the output (0 = minimal, 1 = detailed, 2 = debug).

### Running the Scanner

1. **Basic Scan**:
    To perform a basic scan with default settings:
    ```bash
    python SQLiAS.py http://example.com
    ```

2. **Using Custom Payloads**:
    If you have a file `my_payloads.txt` with custom payloads, use:
    ```bash
    python SQLiAS.py http://example.com --payloads my_payloads.txt
    ```

3. **Setting a Custom Timeout**:
    To set a custom timeout of 5 seconds, use:
    ```bash
    python SQLiAS.py http://example.com --timeout 5
    ```

4. **Adjusting Verbosity**:
    For detailed output, set the verbosity level to 1:
    ```bash
    python SQLiAS.py http://example.com --verbosity 1
    ```

5. **Combining Options**:
    Combine all options for a customized scan:
    ```bash
    python SQLiAS.py http://example.com --payloads my_payloads.txt --timeout 10 --verbosity 2
    ```

## Ethical Considerations

This tool is intended for legal security testing and educational purposes only. Ensure you have explicit permission to test the target application and conduct all activities ethically, adhering to applicable laws and guidelines.
