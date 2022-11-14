FROM ubuntu:jammy

# get software dependencies and Linux headers to compile and run ebpf programs
# uname -r gives different results
RUN apt-get update && \
    apt-get install -y build-essential clang conntrack libcap-dev \
                        libelf-dev net-tools llvm gcc-multilib linux-tools-5.15.0-25-generic \
                        linux-tools-common linux-tools-generic apt-transport-https

# install golang
RUN apt update && \
    apt install -y golang

# enable accessing CA certificates, ping and dig
RUN apt-get update && \
    apt-get -y install curl sudo iputils-ping dnsutils

# current working directory
WORKDIR /build

# download go dependencies
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# set up and build the remaining program
COPY . ./
RUN make