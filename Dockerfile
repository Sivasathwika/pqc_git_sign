FROM ubuntu:22.04

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip git cmake ninja-build gcc g++ libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Build and install liboqs from source
WORKDIR /opt
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && mkdir build && cd build && \
    cmake -GNinja .. && ninja && ninja install && ldconfig

# Copy application files
WORKDIR /app
COPY . /app

# Install Python dependencies
RUN pip3 install --no-cache-dir flask flask-cors liboqs-python --break-system-packages

# Make startup script executable
RUN chmod +x start.sh

EXPOSE 5000
CMD ["./start.sh"]
