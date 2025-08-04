ARG ARCH="amd64"
ARG OS="linux"
FROM quay.io/prometheus/busybox-${OS}-${ARCH}:latest
LABEL maintainer="Giuseppe Di Terlizzi <giuseppe.diterlizzi@gmail.com>"

ARG ARCH="amd64"
ARG OS="linux"
COPY .build/${OS}-${ARCH}/nessus_exporter /bin/nessus_exporter

USER       nobody
ENTRYPOINT ["/bin/nessus_exporter"]
EXPOSE     18834
