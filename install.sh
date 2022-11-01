#!/bin/bash

# Prerequisites: 
# - A server with Debian-based Linux (tested on Ubuntu 22.04)
# - A domain name with at least these subdomains pointing to your server:
#   - example.com
#   - hub.example.com
#   - download.example.com
#   - archive.example.com
#   - assets.example.com
#   - raw.example.com
# - A DNS API key for your domain name provider that is supported by certbot (https://certbot.eff.org/docs/using.html#dns-plugins)
#   Currently supported providers: Cloudflare, DigitalOcean, Linode, Vultr (PR welcome for more)
#   Alternatively, you can get your own *wildcard* SSL certification and deploy it.

# Usage:
# Clone the *full* repository to your server and run this script.

# Add colors
echo_red(){ echo -e "\033[31m\033[01m$1\033[0m"; }
echo_yellow(){ echo -e "\033[33m\033[01m$1\033[0m"; }
echo_green(){ echo -e "\033[32m\033[01m$1\033[0m"; }
reading(){ read -rp "$(echo_green "$1")" "$2"; }

# Check if running as root
if [ `whoami` != "root" ]; then
    echo_red "Root priviledge is required!"
    exit 1
fi

# Check if running on Debian-based system
if [ ! -f "/etc/debian_version" ]; then
    echo_red "This script works on Debian-based distros only! (PR welcome for more distros)"
    exit 1
fi

# Input the domain name
reading "Enter your domain name (e.g. fastgit.org): " DOMAIN

# Setup BBR
if [ `cat /proc/sys/net/ipv4/tcp_congestion_control` != "bbr" ]; then
    read -p "Do you want to enable BBR? (y/n): " USE_BBR
    case $USE_BBR in
        [yY] | [yY][eE][sS] )
            echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
            echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
            sysctl -p
            ;;
        [nN] | [nN][oO] )
            ;;
        * )
            echo "Invalid input!"
            exit 1
            ;;
    esac
fi

echo_yellow "Installing dependencies..."
apt update

echo_yellow "Installing dhparam from Mozilla..."
wget https://ssl-config.mozilla.org/ffdhe2048.txt
mv ffdhe2048.txt ./cert/dhparam.pem
rm ffdhe2048.txt

echo_yellow "Installing nginx configurations..."

# Proceed the configuration files
sed -i "s/fastgit.org/$DOMAIN/g" ./conf.d/*.conf
for file in *fastgit.org.conf; do
    mv "$file" "${file//fastgit.org/$DOMAIN}"
done


docker-compose up

echo_yellow "Enjoy! :D"
