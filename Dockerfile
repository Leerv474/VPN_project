FROM ubuntu:22.04

RUN apt update && apt install -y \
    build-essential \
    cmake \
    libssl-dev \
    libsodium-dev \
    pkg-config \
    nlohmann-json3-dev \
    iproute2 iputils-ping net-tools \
    libstdc++6 \
    iptables iproute2 iputils-ping net-tools \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /app

COPY . .

RUN cmake -S . -B build && cmake --build build

WORKDIR /app/build

CMD ["./vpn", "run"]

