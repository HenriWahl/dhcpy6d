FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-distro python3-dnspython iproute2 iputils-ping tcpdump && rm -rf /var/lib/apt/lists/*
WORKDIR /src
ENTRYPOINT ["python3", "/src/tests/integration/mac_lookup.py"]
