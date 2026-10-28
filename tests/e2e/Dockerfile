FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-dnspython python3-distro python3-scapy \
    iproute2 iptables isc-dhcp-client isc-dhcp-relay dhcpcd-base kea-admin \
    systemd systemd-resolved dbus tcpdump procps ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ENTRYPOINT ["python3", "/src/tests/e2e/run.py"]
