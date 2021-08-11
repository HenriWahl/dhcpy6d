FROM python:3.9
LABEL maintainer=henri@dhcpy6d.de

ARG HTTP_PROXY=""
ENV HTTPS_PROXY $HTTP_PROXY
ENV http_proxy $HTTP_PROXY
ENV https_proxy $HTTP_PROXY

RUN pip install distro \
                dnspython \
                mysqlclient \
                psycopg2

RUN useradd --system --user-group dhcpy6d

WORKDIR /dhcpy6d

CMD python3 main.py --config dhcpy6d.conf --user dhcpy6d --group dhcpy6d

