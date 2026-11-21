#!/usr/bin/env bash
# Installs the lab tools and the test account on Kali, once:
#   sudo bash setup.sh
set -eu
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  curl expect inetutils-inetd inetutils-telnet inetutils-telnetd iputils-ping \
  mitmproxy openssh-client openssh-server openssl python3 testssl.sh tshark

# The telnetd package registers a system-wide Telnet on port 23. lab.sh starts its own on
# 127.0.0.1:2323 only while the test runs, so the system one stays off.
update-inetd --disable telnet
if [ -d /run/systemd/system ]; then systemctl disable --now inetutils-inetd; fi

# Unprivileged test account with a lab-only fake password.
id labuser > /dev/null 2>&1 || useradd -m -s /bin/bash labuser
echo 'labuser:labpass' | chpasswd
