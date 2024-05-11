ARG RYU_VERSION=latest
FROM ghcr.io/scc365/ryu:${RYU_VERSION}

WORKDIR /controller
COPY controller.py .

EXPOSE 6633

CMD [ "--ofp-tcp-listen-port", "6633", "--verbose", "./controller.py" ]