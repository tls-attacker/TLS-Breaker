FROM ubuntu:22.04

# Update the package manager and install required packages:
# - openjdk-11-jdk: Java Development Kit for running Java applications
# - libpcap-dev: Development library for packet capture
# - tcpdump: Tool for network traffic analysis
# Clean up the package cache to reduce image size
RUN apt update && apt install -y \
    openjdk-11-jdk \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container to /app
WORKDIR /app

# Copy the contents of the local "app/" directory to the container's /app/ directory
COPY app/ /app/

# Set the default command to start a bash shell
CMD ["bash"]
