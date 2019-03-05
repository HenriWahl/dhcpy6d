FROM debian:testing
LABEL maintainer=h.wahl@ifw-dresden.de

# just in case a proxy is needed
ARG HTTP_PROXY=
ENV HTTPS_PROXY $HTTP_PROXY
ENV http_proxy $HTTP_PROXY
ENV https_proxy $HTTP_PROXY

# prepare apt
ARG DEBIAN_FRONTEND=noninteractive
RUN apt -y update
RUN apt -y install apt-utils
RUN apt -y upgrade

# prerequisites for package building
RUN apt -y install build-essential devscripts dh-systemd dh-python git python-all python-docutils sudo
