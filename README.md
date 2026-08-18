Local Password and Credential Audit Script
Overview

This PowerShell script performs a comprehensive local credential and password exposure audit on Windows endpoints. It is designed to help security teams, administrators, and compliance auditors identify stored credentials, potentially exposed passwords in local files, and browser-saved account information.

The script generates a consolidated CSV report containing discovered credential-related artifacts together with system metadata such as hostname, username, and IP address.

Features
1. Windows Credential Manager Audit
Enumerates credentials stored in Windows Credential Manager using cmdkey.
Falls back to vaultcmd when Credential Manager data cannot be retrieved.
Identifies saved application, network, and domain credentials.
2. Local File Password Discovery
Scans all connected local fixed drives.
Searches common configuration and data file formats, including:
.config
.xml
.json
.ini
.txt
.csv
.env
.conf
.cfg
.ps1
.bat
.sh
.key
.pem
Office documents (.docx, .xlsx, etc.)
Detects common password-related keywords:
password=
pwd=
secret=
api_key=
passwd=
Skips cloud-only/offline files to avoid unnecessary downloads from cloud storage providers.
Excludes standard system folders such as:
C:\Windows
C:\Program Files
C:\ProgramData
3. Browser Credential Inventory

The script identifies websites for which credentials are stored in major browsers.

Chromium-Based Browsers
Google Chrome
Microsoft Edge
Brave Browser
Opera Stable

The script:

Locates browser profile databases.
Enumerates saved login entries.
Extracts associated domains/URLs.
Reports credential storage locations by browser profile.
Mozilla Firefox
Processes Firefox profile directories.
Reads credential metadata from logins.json.
Identifies websites with saved credentials.
4. Audit Reporting
Generates a consolidated CSV report.
Includes system identification metadata:
Host Name
Username
IP Address
Stores output in:
%USERPROFILE%\Downloads\CredentialAuditReport.csv

Output Categories

The report may contain entries in the following categories:

Category	DescriptionCredential Manager Stored Key	Credentials stored within Windows Credential Manager
Credential Manager Vault	Credential vault containers discovered
Potential File Exposure	Files containing password-related keywords
Saved Browser Account	Websites for which browser credentials are stored
Intended Use Cases
Security self-assessments
Endpoint credential hygiene reviews
Compliance audits
Internal security investigations
Validation of password storage practices
Preparation for security audits and attestations
Requirements
Windows operating system
PowerShell 5.1 or later
Local user permissions to access profile and file system data
Access to browser profile directories
Notes
The script does not decrypt browser passwords.
Only metadata and credential storage locations are collected.
Browser audit results identify domains associated with stored credentials rather than exposing credential values.
Large file systems may significantly increase scan duration.
Results should be reviewed carefully before being shared, as they may contain sensitive information discovered during the audit.
Disclaimer

This script is intended for authorized security auditing and compliance purposes only. Run it only on systems that you own or are explicitly authorized to audit. Any collected information should be handled according to your organization's security and data protection policies.
