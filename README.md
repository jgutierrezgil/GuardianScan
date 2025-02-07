# GuardianScan
#### Video Demo:  <URL HERE>
#### Description:
# Welcome to **GuardianScan**

GuardianScan is a web security analysis tool developed as the final project for Harvard University's CS50 course. This tool is designed to help identify common vulnerabilities in web applications, with a primary focus on **Cross-Site Scripting (XSS)** and **SQL Injection (SQLi)**.

## How It Works

GuardianScan allows users to specify a target URL and automatically crawls all internal links within the site. For each discovered link, the tool sends specially crafted payloads to test whether the page is susceptible to malicious code injection or database manipulation. 

- **XSS Testing**: The tool checks if harmful scripts can be injected into the application, potentially compromising user sessions or stealing sensitive data.
- **SQLi Testing**: GuardianScan evaluates whether the application is vulnerable to SQL queries that could expose or manipulate database content.

## Key Features

- **Automated Crawling**: Scans all internal links within the target site to ensure comprehensive testing.
- **Payload Testing**: Sends a variety of pre-defined or custom payloads to detect vulnerabilities.
- **Detailed Reporting**: Logs successful payloads and provides a comprehensive report highlighting which parts of the application are at risk.
- **Educational Value**: Demonstrates fundamental concepts of web security, making it an excellent learning resource for developers, security researchers, and site owners.

## Why Use GuardianScan?

By identifying potential vulnerabilities, GuardianScan empowers developers and site owners to remediate flaws before they can be exploited by attackers. While this tool serves as a practical starting point for understanding web security, it also highlights the importance of secure coding practices and proactive vulnerability management.

Whether you're a beginner exploring the world of cybersecurity or a seasoned professional looking to enhance your toolkit, GuardianScan provides valuable insights into the detection and prevention of common web vulnerabilities.

---

**Note**: This tool is intended for educational purposes and ethical use only. Always ensure you have explicit permission before scanning any website.