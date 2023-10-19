FROM golang:bullseye

RUN apt-get update && \
    apt-get install -y \
    build-essential \
    autoconf-archive \
    autoconf \
    pkg-config \
    libtool \
    automake \
    libssl-dev \
    libcurl4-gnutls-dev \
    python3-yaml \
    libjson-c-dev \
    libglib2.0-dev \
    uuid-dev \
    dbus-daemon \
    gosu \
    neovim \
    curl \
    zsh \
    netcat \
    protobuf-compiler \
    jq

# Single run optimises the image size
RUN mkdir /tools && cd /tools && git clone --branch 4.0.x --depth 1 https://github.com/tpm2-software/tpm2-tss.git && \
    cd tpm2-tss && \
    ./bootstrap && \
    ./configure --prefix=/usr && \
    make -j5 && \
    make install && \
    git clone --depth 1 https://github.com/tpm2-software/tpm2-abrmd.git && \
    cd tpm2-abrmd && \
    ./bootstrap && \
    ./configure --with-dbuspolicydir=/etc/dbus-1/system.d \
    --with-udevrulesdir=/usr/lib/udev/rules.d \
    --with-systemdsystemunitdir=/usr/lib/systemd/system \
    --libdir=/usr/lib --prefix=/usr && \
    make -j5 && \
    make install && \
    git clone --depth 1  https://github.com/tpm2-software/tpm2-tools.git && \
    cd tpm2-tools && \
    ./bootstrap && \
    ./configure --prefix=/usr && \
    make -j5 && \
    make install && \
    git clone --depth 1 https://github.com/microsoft/ms-tpm-20-ref && \
    cd ms-tpm-20-ref/TPMCmd/ && \
    bash bootstrap && \
    ./configure && \
    make && \
    cp Simulator/src/tpm2-simulator /usr/bin/tpm2-simulator && \
    # Needed for DBUS to work
    mkdir -p /run/dbus && \ 
    rm -rf /tools/ 

WORKDIR /root

RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest

COPY entrypoint.sh /tools/entrypoint.sh

ENV USER_NAME root
ENV CGO_CFLAGS="-Wno-psabi

ENTRYPOINT ["/tools/entrypoint.sh"]
CMD ["zsh"]
