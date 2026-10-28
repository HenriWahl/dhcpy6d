FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    adduser lsb-base python3 python3-distro python3-dnspython ucf systemd rpm \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT []
