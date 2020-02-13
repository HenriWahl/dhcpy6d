FROM python:3.7
LABEL maintainer=h.wahl@ifw-dresden.de

ARG HTTP_PROXY=""
ENV HTTPS_PROXY $HTTP_PROXY
ENV http_proxy $HTTP_PROXY
ENV https_proxy $HTTP_PROXY

RUN pip install distro \
                dnspython \
                mysqlclient \
                psutil \
                psycopg2

RUN useradd --system --user-group dhcpy6d



