#!/bin/env python3

# 这个脚本可以用来设置 DNS 记录.
# FastGit 目前需要用到的 DNS 记录有: 
#   - example.com
#   - hub.example.com
#   - download.example.com
#   - archive.example.com
#   - raw.example.com
#   - assets.example.com

# 准备工作: 
#   - Python 3.6+
#   - pip install dnspython
#   - 一个使用以下 DNS 提供商的域名: 
#     目前支持的 DNS 提供商有（欢迎 PR）: 
#       - Cloudflare
#       - DigitalOcean
#       - DNSPod
#       - Vultr
#       - GoDaddy
#       - Linode
#   - 一个 API Token, 用于修改 DNS 记录

# 使用方法: 
#   - python dns-setup.py -h|--help
#   - python dns-setup.py -t <token> -d <域名> # 例如 python dns-setup.py -t 1234567890abcdef -d example.com

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
                print(f"警告: 不使用这个无法公开访问的地址 {addr}")

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
                print(f"警告: 不使用这个无法公开访问的地址 {addr}")
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
        print(f"错误: 域名 {domain} 不存在")
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
        print("错误：获取域名 ID 失败")
        sys.exit(1)
    except StopIteration:
        print("错误：未在您的 Linode 账户中找到此域名")
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
    parser = argparse.ArgumentParser(description="为部署 FastGit 项目的域名设置 DNS 记录")
    pa = parser.add_argument
    pa("--domain", "-d", type=str, help="要更新的域名")
    pa("--token", "-t", type=str, help="DNS 提供商的 API token")
    pa("--ipv4", "-4", type=str, help="要使用的 IPv4 地址", default=None)
    pa("--ipv6", "-6", type=str, help="要使用的 IPv6 地址", default=None)
    pa("--test", action="store_true", help="测试模式, 不会真正更新 DNS 记录")
    pa("--non-interactive", "-n", action="store_true", help="非交互模式, 不会提示用户输入 \n 请确保已经正确设置了 --domain 和 --token")
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
            print("错误: 未指定域名")
            sys.exit(1)
        else:
            domain = input("请输入域名: ")
    if not token:
        if isNonInteractive:
            print("错误: 未指定 API token")
            sys.exit(1)
        else:
            token = input("请输入 API token: ")

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
        print(f"不支持的 DNS 提供商:  {nameServers[0]}")
        sys.exit(1)
    print("使用 DNS 提供商", provider)

    # Get the domain's A and AAAA records
    aRecords = get_dns_records(domain, "A")
    aaaaRecords = get_dns_records(domain, "AAAA")
    if aRecords:
        print(f"当前域名的 A 记录 \"{domain}\": {aRecords}")
        askIfChange = True
    if aaaaRecords:
        print(f"当前域名的 AAAA 记录\"{domain}\": {aaaaRecords}")
        askIfChange = True
    if askIfChange and not isNonInteractive:
        if input("是否要更改这些记录？[y/N]:") != "y":
            sys.exit(0)

    # Get the IP addresses

    # First, try to get the IP addresses from the command line arguments
    if ipv4 or ipv6:
        # Validate the IP addresses
        if ipv4 and not re.match(r"^(\d{1,3}\.){3}\d{1,3}$", ipv4):
            print(f"无效的地址:  {ipv4}")
            sys.exit(1)
        else:
            print(f"使用命令行指定的地址:  {ipv4}")

        if ipv6 and not re.match(r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$", ipv6):
            print(f"无效的地址:  {ipv6}")
            sys.exit(1)
        else:
            print(f"使用命令行指定的地址:  {ipv6}")

    # Second, try to get the IP addresses from the local network interfaces
    else:
        # Get the IP addresses of the local network interfaces
        ipv4 = get_local_ipv4_address()
        ipv6 = get_local_ipv6_address()
        if ipv4 or ipv6:
            print("使用本地网络接口的地址: ")
            if ipv4:
                print(f"IPv4: {ipv4}")
            if ipv6:
                print(f"IPv6: {ipv6}")
    
    # Third, try to get the public IP addresses from the Internet
    if not ipv4 or not ipv6:
        ipv4 = get_public_ipv4_address()
        ipv6 = get_public_ipv6_address()
        if ipv4 or ipv6:
            print("使用公共 IP 地址: ")
            if ipv4:
                print(f"IPv4: {ipv4}")
            if ipv6:
                print(f"IPv6: {ipv6}")
    
    # If no IP addresses were found, exit
    if not ipv4 and not ipv6:
        print("未找到 IP 地址")
        sys.exit(1)
    
    # Ask the user to confirm the IP addresses
    if not isNonInteractive:
        if input("是否使用这些 IP 地址？[y/N]:") != "y":
            sys.exit(0)

    # Update the domain's A and AAAA records
    if not isTest:
        if ipv4:
            set_dns_records(domain, "A", ipv4, token)
        if ipv6:
            set_dns_records(domain, "AAAA", ipv6, token)
    else:
        print("测试模式, 不会更新 DNS 记录")

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
    print("更新完成, 请等待几分钟后 DNS 记录生效")


if __name__ == "__main__":
    main()