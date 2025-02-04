
# CVE-2014-0160

## Overview

This script is designed to test and potentially exploit the Heartbleed vulnerability (CVE-2014-0160) in TLS/SSL protocols. Heartbleed is a critical security flaw that allows attackers to read sensitive memory content from vulnerable servers.

The script sends specially crafted TLS heartbeat requests to the target server and analyzes the server's response to determine whether it is vulnerable.

## Features

-Test TLS/SSL servers for the Heartbleed vulnerability.

-Verbose output for detailed inspection.

-Adjustable payload length for heartbeat requests.

-Python 2.7 compatible.

## Prerequisites

-Python 2.7

-Network connectivity to the target server.

-Permissions to run the script (chmod +x script.py).

## Usage

Basic Command Structure

```python
python script.py <server> [options]
```

## Options

-p, --port (default: 443): Specify the TCP port.

-l, --length (default: 0x4000): Set the payload length.

-s, --starttls: Use STARTTLS for SMTP, POP3, IMAP, or FTP.

-v, --verbose: Enable detailed verbose output.

## Examples

Basic Heartbleed Test: 

```python
python example.com -p 8443 
```
## Output

If the server is vulnerable, the script will display a message indicating that the Heartbeat response returned more data than expected.

Verbose mode (-v) will display detailed information about the TLS communication.

## Disclaimer

This script is intended for educational and authorized security testing purposes only. Unauthorized use against systems you do not own or have explicit permission to test is illegal.

Use responsibly!

[LEARN MORE](https://en.wikipedia.org/wiki/Heartbleed)
