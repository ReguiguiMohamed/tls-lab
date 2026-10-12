FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      curl expect inetutils-inetd inetutils-telnet inetutils-telnetd iputils-ping \
      openssh-client openssh-server openssl python3 testssl.sh tshark \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /lab
# Compte de test sans privilèges, mot de passe fictif propre au laboratoire.
RUN useradd -m -s /bin/bash labuser && echo 'labuser:labpass' | chpasswd
