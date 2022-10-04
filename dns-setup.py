#!/bin/env python3

# This script can help you to setup DNS records for your domain.
# These subdomains will be used by fastgit:
#   - example.com
#   - hub.example.com
#   - download.example.com
#   - archive.example.com
#   - raw.example.com
#   - assets.example.com

# Prerequisites:
#   - Python 3.6+
#   - pip install dnspython
#   - A domain that uses supported DNS provider
#     Currently supported DNS providers (PR welcome for more providers):
#       - Cloudflare
#       - DigitalOcean
#       - DNSPod
#       - Vultr
#       - GoDaddy
#       - Linode
#   - A valid API token for your DNS provider

# Usage:
#   - python dns-setup.py -h|--help
#   - python dns-setup.py -t <token> -d <domain> # Provider will be detected automatically

import argparse
import json
import os
import sys
import time
from typing import List, Optional
import re
import ipaddress
import dns.resolver
import requests
import socket

DNS_RECORD_TTL = 1800

DNS_RECORDS = ["@", "hub", "download", "archive", "raw", "assets"]

JSON_CONTENT_TYPE = "application/json"

def get_local_ipv4_address() -> Optional[str]:
    for line in os.popen("ip addr show").readlines():
        m = re.search(r"inet\s+([0-9.]+)", line)
        if m:
            ip = m.group(1)
            # Ignore loopback address and private address
            if ipaddress.ip_address(ip).is_loopback or ipaddress.ip_address(ip).is_private:
                continue
            return ip
    return None

def get_local_ipv6_address() -> Optional[str]:
    for line in os.popen("ip addr show").readlines():
        m = re.search(r"inet6\s+([0-9a-f:]+)", line)
        if m:
            ip = m.group(1)
            # Ignore loopback address and private address
            if ipaddress.ip_address(ip).is_loopback or ipaddress.ip_address(ip).is_private:
                continue
            return ip
    return None

# We must get the IP address with port open.
# Thanks https://www.ipify.org/ for providing public IP address API.
def get_public_ipv4_address() -> Optional[str]:
    # First, try to get the IP address from ipify.org
    try:
        response = requests.get("https://api.ipify.org")
        response.raise_for_status()
        addr = response.text

        # Then, listen on port 80 and 443 to check if the IP address is accessible
        if addr:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            if s.connect_ex((addr, 80)) == 0 and s.connect_ex((addr, 443)) == 0:
                return addr
            else:
                print(f"Warning: Not using {addr} because it's not accessible publicly")

        return None

    except requests.exceptions.RequestException:
        return None
    
def get_public_ipv6_address() -> Optional[str]:
    # First, try to get the IP address from ipify.org
    try:
        response = requests.get("https://api6.ipify.org")
        response.raise_for_status()
        addr = response.text

        # Then, listen on port 80 and 443 to check if the IP address is accessible
        if addr:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s.settimeout(3)
            if s.connect_ex((addr, 80)) == 0 and s.connect_ex((addr, 443)) == 0:
                return addr
            else:
                print(f"Warning: Not using {addr} because it's not accessible publicly")
        return None

    except requests.exceptions.RequestException:
        return None


def get_dns_records(domain: str, record_type: str) -> List[str]:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
    resolver.use_edns = True # Use DNS over HTTPS to avoid DNS pollution
    try:
        answers = resolver.resolve(domain, record_type)
    except dns.resolver.NXDOMAIN:
        print(f"Error: Domain {domain} not found")
        sys.exit(1)
    except dns.resolver.NoAnswer:
        return []
    return [str(answer) for answer in answers]

# Cloudflare API reference: https://api.cloudflare.com/
def set_dns_records_cloudflare(domain: str, record_type: str, record: str, token: str) -> bool:
    for subdomain in DNS_RECORDS:
        headers = {
            "Content-Type": JSON_CONTENT_TYPE,
            "Authorization": f"Bearer {token}",
        }
        data = {
            "type": record_type,
            "name": f"{subdomain}.{domain}",
            "content": record,
            "ttl": DNS_RECORD_TTL,
            "proxied": False, # We don't use Cloudflare CDN
        }
        try:
            response = requests.post(
                f"https://api.cloudflare.com/client/v4/zones/{domain}/dns_records",
                headers=headers,
                data=json.dumps(data),
            )
            response.raise_for_status()
        except requests.exceptions.RequestException:
            print(response.text)
            return False
    return True

# GoDaddy API reference: https://developer.godaddy.com/doc
def set_dns_records_godaddy(domain: str, record_type: str, record: str, token: str) -> bool:
    for subdomain in DNS_RECORDS:
        headers = {
            "Content-Type": JSON_CONTENT_TYPE,
            "Authorization": f"sso-key {token}",
        }
        data = {
            "data": record,
            "ttl": DNS_RECORD_TTL,
        }
        try:
            response = requests.put(
                f"https://api.godaddy.com/v1/domains/{domain}/records/{record_type}/{subdomain}",
                headers=headers,
                data=json.dumps(data),
            )
            response.raise_for_status()
        except requests.exceptions.RequestException:
            print(response.text)
            return False
    return True

# DigitalOcean API reference: https://developers.digitalocean.com/documentation/v2/
def set_dns_records_digitalocean(domain: str, record_type: str, record: str, token: str) -> bool:
    for subdomain in DNS_RECORDS:
        headers = {
            "Content-Type": JSON_CONTENT_TYPE,
            "Authorization": f"Bearer {token}",
        }
        data = {
            "type": record_type,
            "name": subdomain,
            "data": record,
            "ttl": DNS_RECORD_TTL,
        }
        try:
            response = requests.post(
                f"https://api.digitalocean.com/v2/domains/{domain}/records",
                headers=headers,
                data=json.dumps(data),
            )
            response.raise_for_status()
        except requests.exceptions.RequestException:
            print(response.text)
            return False
    return True

# DNSPod API reference: https://www.dnspod.cn/docs/index.html
def set_dns_records_dnspod(domain: str, record_type: str, record: str, token: str) -> bool:
    for subdomain in DNS_RECORDS:
        headers = {
            "Content-Type": JSON_CONTENT_TYPE,
            "Authorization": f"Bearer {token}",
        }
        data = {
            "domain": domain,
            "record_type": record_type,
            "sub_domain": subdomain,
            "record_line": "默认",
            "value": record,
            "ttl": DNS_RECORD_TTL,
        }
        try:
            response = requests.post(
                "https://dnsapi.cn/Record.Create",
                headers=headers,
                data=json.dumps(data),
            )
            response.raise_for_status()
        except requests.exceptions.RequestException:
            print(response.text)
            return False
    return True

# Vultr API reference: https://www.vultr.com/api/
def set_dns_records_vultr(domain: str, record_type: str, record: str, token: str) -> bool:
    for subdomain in DNS_RECORDS:
        headers = {
            "Content-Type": JSON_CONTENT_TYPE,
            "Authorization": f"Bearer {token}",
        }
        data = {
            "name": subdomain,
            "type": record_type,
            "data": record,
            "ttl": DNS_RECORD_TTL,
        }
        try:
            response = requests.post(
                f"https://api.vultr.com/v2/domains/{domain}/records",
                headers=headers,
                data=json.dumps(data),
            )
            response.raise_for_status()
            return True
        except requests.exceptions.RequestException:
            print(response.text)
            return False
    return True

# Linode API reference: https://developers.linode.com/api/v4/
def set_dns_records_linode(domain: str, record_type: str, record: str, token: str) -> bool:
    headers = {
        "Content-Type": JSON_CONTENT_TYPE,
        "Authorization": f"Bearer {token}",
    }
    # First, get the domain ID
    try:
        response = requests.get(
            f"https://api.linode.com/v4/domains",
            headers=headers,
        )
        response.raise_for_status()
        domains = response.json()["data"]
        domain_id = next(domain["id"] for domain in domains if domain["domain"] == domain)
    except requests.exceptions.RequestException:
        print(response.text)
        print("Error: Unable to get domain ID (Network error)")
        sys.exit(1)
    except StopIteration:
        print("Error: Domain not found in your Linode account")
        sys.exit(1)
    # Then, set the DNS records
    for subdomain in DNS_RECORDS:
        data = {
            "type": record_type,
            "name": subdomain,
            "target": record,
            "ttl_sec": DNS_RECORD_TTL,
        }
        try:
            response = requests.post(
                f"https://api.linode.com/v4/domains/{domain_id}/records",
                headers=headers,
                data=json.dumps(data),
            )
            response.raise_for_status()
        except requests.exceptions.RequestException:
            print(response.text)
            return False
    return True

# Parse the command line arguments
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Update DNS records for a domain to work with FastGit")
    pa = parser.add_argument
    pa("--domain", "-d", type=str, help="The domain to update")
    pa("--token", "-t", type=str, help="The token to authenticate with the DNS provider")
    pa("--ipv4", "-4", type=str, help="The IPv4 address to use", default=None)
    pa("--ipv6", "-6", type=str, help="The IPv6 address to use", default=None)
    pa("--test", action="store_true", help="Test mode, print the DNS record instead of updating it")
    pa("--non-interactive", "-n", action="store_true", help="Non-interactive mode, do not ask for confirmation\nPlease specify the domain and token in this mode")
    return parser.parse_args()

# Main function
def main() -> None:
    args = parse_args()
    domain = args.domain
    token = args.token
    ipv4 = args.ipv4
    ipv6 = args.ipv6
    isTest = args.test
    isNonInteractive = args.non_interactive

    # If the user didn't input arguments, ask for them
    if not domain:
        if isNonInteractive:
            print("Error: Domain not specified")
            sys.exit(1)
        else:
            domain = input("Enter your Domain (example.com):")
    if not token:
        if isNonInteractive:
            print("Error: Token not specified")
            sys.exit(1)
        else:
            token = input("Enter your Token:")

    # Validate the domain and its name servers
    #  - Cloudflare nameservers: *.ns.cloudflare.com
    #  - GoDaddy nameservers: *.godaddy.com
    #  - DigitalOcean nameservers: ns1.digitalocean.com, ns2.digitalocean.com, ns3.digitalocean.com
    #  - DNSPod nameservers: ns1.dnspod.net, ns2.dnspod.net, ns3.dnspod.net
    #  - Vultr nameservers: ns1.vultr.com, ns2.vultr.com
    #  - Linode nameservers: ns1.linode.com, ns2.linode.com, ns3.linode.com, ns4.linode.com, ns5.linode.com

    # Check if the domain is valid
    if not re.match(r"^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$", domain):
        print(f"Invalid domain: {domain}")
        sys.exit(1)

    # Get the domain's name servers
    nameServers = get_dns_records(domain, "NS")
    if nameServers[0].__contains__("ns.cloudflare.com"):
        provider = "cloudflare"
        set_dns_records = set_dns_records_cloudflare
    elif nameServers[0].__contains__("godaddy.com"):
        provider = "godaddy"
        set_dns_records = set_dns_records_godaddy
    elif nameServers[0].__contains__("digitalocean.com"):
        provider = "digitalocean"
        set_dns_records = set_dns_records_digitalocean
    elif nameServers[0].__contains__("dnspod.net"):
        provider = "dnspod"
        set_dns_records = set_dns_records_dnspod
    elif nameServers[0].__contains__("vultr.com"):
        provider = "vultr"
        set_dns_records = set_dns_records_vultr
    elif nameServers[0].__contains__("linode.com"):
        provider = "linode"
        set_dns_records = set_dns_records_linode
    else:
        print(f"Unsupported DNS provider: {nameServers[0]}")
        sys.exit(1)
    print("Using DNS provider:", provider)

    # Get the domain's A and AAAA records
    aRecords = get_dns_records(domain, "A")
    aaaaRecords = get_dns_records(domain, "AAAA")
    if aRecords:
        print(f"Current A records of \"{domain}\": {aRecords}")
        askIfChange = True
    if aaaaRecords:
        print(f"Current AAAA records of \"{domain}\": {aaaaRecords}")
        askIfChange = True
    if askIfChange and not isNonInteractive:
        if input("Do you want to change the records? [y/N]:") != "y":
            sys.exit(0)

    # Get the IP addresses

    # First, try to get the IP addresses from the command line arguments
    if ipv4 or ipv6:
        # Validate the IP addresses
        if ipv4 and not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ipv4):
            print(f"Invalid IPv4 address: {ipv4}")
            sys.exit(1)
        else:
            print(f"Using IPv4 address from command line argument: {ipv4}")

        if ipv6 and not re.match(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$", ipv6):
            print(f"Invalid IPv6 address: {ipv6}")
            sys.exit(1)
        else:
            print(f"Using IPv6 address from command line argument: {ipv6}")

    # Second, try to get the IP addresses from the local network interfaces
    else:
        # Get the IP addresses of the local network interfaces
        ipv4 = get_local_ipv4_address()
        ipv6 = get_local_ipv6_address()
        if ipv4 or ipv6:
            print("Using IP addresses from local network interfaces:")
            if ipv4:
                print(f"IPv4: {ipv4}")
            if ipv6:
                print(f"IPv6: {ipv6}")
    
    # Third, try to get the public IP addresses from the Internet
    if not ipv4 or not ipv6:
        ipv4 = get_public_ipv4_address()
        ipv6 = get_public_ipv6_address()
        if ipv4 or ipv6:
            print("Using IP addresses detected from the Internet:")
            if ipv4:
                print(f"IPv4: {ipv4}")
            if ipv6:
                print(f"IPv6: {ipv6}")
    
    # If no IP addresses were found, exit
    if not ipv4 and not ipv6:
        print("No usable public IP addresses found")
        sys.exit(1)
    
    # Ask the user to confirm the IP addresses
    if not isNonInteractive:
        if input("Do you want to use these IP addresses? [y/N]:") != "y":
            sys.exit(0)

    # Update the domain's A and AAAA records
    if not isTest:
        if ipv4:
            set_dns_records(domain, "A", ipv4, token)
        if ipv6:
            set_dns_records(domain, "AAAA", ipv6, token)
    else:
        print("Test mode, no changes were made")

    '''
    # Wait for the DNS records to propagate
    print("Waiting 30s for the DNS records to propagate...")
    time.sleep(30)

    # Get the domain's A and AAAA records again and check if they are correct
    aRecords = get_dns_records(domain, "A")
    aaaaRecords = get_dns_records(domain, "AAAA")
    if aRecords:
        print(f"New A records of \"{domain}\": {aRecords}")
    if aaaaRecords:
        print(f"New AAAA records of \"{domain}\": {aaaaRecords}")
    '''
    print("Done! Wait a few minutes for the changes to propagate.")


if __name__ == "__main__":
    main()