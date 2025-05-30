FROM ubuntu:22.04

# Install build tools, CMake, and dependencies
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

# Copy everything into container
COPY . .

# Create build dir and build using CMake
RUN cmake -S . -B build && cmake --build build

# Set default working dir to the build output
WORKDIR /app/build

# Default command (can be overridden in docker-compose)
CMD ["./vpn", "run"]

