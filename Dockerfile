FROM ubuntu:21.04 AS builder
RUN apt-get update
RUN apt-get -y install curl flex bison libssl-dev python-dev libgmp-dev wget build-essential

RUN curl -OL https://golang.org/dl/go1.16.7.linux-amd64.tar.gz && tar -C /usr/local -xvf go1.16.7.linux-amd64.tar.gz
ENV PATH=$PATH:/usr/local/go/bin

ARG sa_enabled=false

WORKDIR /build

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY / .

RUN set -eux; \
    mkdir temp && cd temp && mkdir pbc && \
    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz -O pbc.tar.gz && \
    tar -zxvf pbc.tar.gz && \
    cd pbc-0.5.14 && \
    ./configure && \
    make && \
    make install

RUN mkdir -p /build/bin \
    && go build -ldflags "-X abe/plugin.sa_enabled=$sa_enabled" -o /build/bin/abe . \
    && sha256sum -b /build/bin/abe > /build/bin/SHA256SUMS

# VAULT
FROM vault:1.8.0
ARG always_upgrade
RUN echo ${always_upgrade} >/dev/null && apk update && apk upgrade
RUN apk add bash openssl jq


RUN set -eux; \
    apk add --no-cache musl build-base flex bison gmp-dev

RUN set -eux; \
    mkdir temp && cd temp && mkdir pbc && \
    wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz -O pbc.tar.gz && \
    tar -zxvf pbc.tar.gz && \
    cd pbc-0.5.14 && \
    ./configure && \
    make && \
    make install

RUN export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib
RUN export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib 

# RUN cp /usr/local/lib/* /usr/lib/

ENV GLIBC_REPO=https://github.com/sgerrand/alpine-pkg-glibc
ENV GLIBC_VERSION=2.32-r0
RUN set -ex && \
    apk --update add libstdc++ curl ca-certificates && \
    for pkg in glibc-${GLIBC_VERSION} glibc-bin-${GLIBC_VERSION}; \
        do curl -sSL ${GLIBC_REPO}/releases/download/${GLIBC_VERSION}/${pkg}.apk -o /tmp/${pkg}.apk; done && \
    apk add --allow-untrusted /tmp/*.apk && \
    rm -v /tmp/*.apk && \
    /usr/glibc-compat/sbin/ldconfig /lib /usr/glibc-compat/lib

USER vault

WORKDIR /vault

RUN chown -R vault:vault .

COPY --from=builder /build/bin/abe /vault/plugins/abe
COPY --from=builder /build/bin/SHA256SUMS /vault/plugins/SHA256SUMS
