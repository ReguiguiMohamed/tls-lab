FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
COPY setup.sh /tmp/setup.sh
RUN bash /tmp/setup.sh && rm -rf /var/lib/apt/lists/* /tmp/setup.sh
WORKDIR /lab
