# Vibe Dumper

A security assessment tool that scans websites for exposed Supabase JWT tokens and dumps accessible database tables to identify sensitive data exposure.
![vibe-dumper](https://github.com/user-attachments/assets/d55d02ea-a0c2-4088-b922-cadac3d217a6)

## Overview

Vibe Dumper automates the process of discovering Supabase instances in JavaScript files and testing their security posture. If a JWT token is found, the script attempts to enumerate and dump accessible tables, analyzing them for sensitive information.

## Features

- Scans websites for Supabase JWT tokens in JavaScript files
- Automatically discovers Supabase project URLs from frontend code
- Enumerates accessible database tables using exposed credentials
- Analyzes dumped data for sensitive fields (emails, passwords, tokens, PII, etc.)
- Categorizes vulnerabilities by severity level (critical, high, medium)
- Generates detailed JSON reports for each target
- Multi-threaded scanning for improved performance
- Batch scanning from file input or single URL testing
- Error handling to continue scanning even if individual targets fail

# Installation
### Requirements

See `requirements.txt`:
- requests >= 2.31.0
- beautifulsoup4 >= 4.12.0
- urllib3 >= 2.0.0
- tqdm >= 4.66.0

### Setup

1. Clone or download the repository:
```bash
cd vibe-dumper
```

2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

Or let the script install them automatically on first run.

## Usage

### Single URL Scan

```bash
python3 vibe-dumper.py --url https://example.com
```

### Batch Scanning from File

```bash
python3 vibe-dumper.py --file targets.txt
```

Or place URLs in a `sites.txt` file and run without arguments:
```bash
python3 vibe-dumper.py
```

### Advanced Options

```bash
python3 vibe-dumper.py --url https://example.com --threads 10 --output ./results
```

**Available Arguments:**
- `--url`: Single URL to scan
- `--file`: File containing URLs (one per line)
- `--threads`: Number of concurrent workers for table processing (default: 5)
- `--output`: Output directory for results (default: ./output)

## Output

Results are organized by domain in the output directory:

```
output/
  example.com/
    findings.json          # Complete scan findings
    summary.json           # Table processing summary
    tables/
      users.json           # Dumped table data
      products.json
```

## Vulnerability Detection

The tool identifies sensitive data through:

- Field name analysis (email, password, token, ssn, etc.)
- Pattern matching (JWTs, credit cards, phone numbers)
- Content analysis of actual data values
- PII detection (personally identifiable information)

Vulnerabilities are categorized as:
- **Critical**: Password hashes, API keys, JWTs, credit cards
- **High**: Email addresses, phone numbers with sensitive context
- **Medium**: Other identified sensitive fields


## Security Notice

This tool is designed for authorized security testing and vulnerability assessment only. Unauthorized access to computer systems is illegal. Only scan systems you own or have explicit written permission to test.
