# Advanced SQL Injection (SQLi) Scanner Tool

The Advanced SQL Injection Scanner is a sophisticated, Python-based tool crafted for security analysts and penetration testers. It automates the detection of SQL Injection vulnerabilities in web applications by sending varied SQLi payloads to specified URLs and analyzing the responses for signs of injectable parameters. This tool aids in uncovering potential vulnerabilities that could allow unauthorized manipulation or access to an application's underlying database.

## Key Features

- **Custom Payloads**: Ability to use a custom list of SQLi payloads, enhancing targeted testing based on specific application contexts or tester insights.
- **Request Timeouts**: Supports custom request timeouts to adapt to different network conditions and prevent potential target server overloads.
- **Verbosity Levels**: Offers multiple verbosity levels for output, from minimal to debug, providing flexible feedback suited to various use cases.
- **Multiple Testing Methods**: Capable of testing GET and POST parameters, alongside automatic form detection and testing within HTML content (requires BeautifulSoup4).
- **Comprehensive Vulnerability Detection**: Employs a wide range of payloads (error-based, boolean-based, time-based) to identify various forms of SQLi vulnerabilities.
- **Ease of Use**: Despite its depth, the tool is user-friendly, offering an intuitive command-line interface suitable for all user levels.

## Usage Scenarios

- **Penetration Testing**: An asset in authorized penetration testing efforts, helping identify SQLi vulnerabilities for further testing and remediation.
- **Security Assessments**: Useful in regular security assessments to identify and mitigate SQL Injection risks in web applications.
- **Educational Purposes**: Beneficial for educational demonstrations and studies on SQL Injection vulnerability detection and impact.

## Ethical Considerations

This tool is designed for authorized security testing and educational purposes only. Users must have explicit permission to test the target applications and conduct all activities ethically, adhering to all relevant laws and guidelines.

## Commands

The tool is invoked from the command line, with the syntax and options detailed below:

Basic command structure:
