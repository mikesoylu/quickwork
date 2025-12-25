# Build stage - use Alpine for building
FROM alpine:3.20 AS builder

# Install build dependencies (use clang for better C++ compatibility with QuickJS)
RUN apk add --no-cache \
    clang \
    cmake \
    curl-dev \
    git \
    linux-headers \
    make \
    musl-dev \
    openssl-dev

WORKDIR /build

# Copy source files
COPY CMakeLists.txt ./
COPY include/ ./include/
COPY src/ ./src/

# Build with dynamic linking (simpler and more reliable)
RUN cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER=clang \
    -DCMAKE_CXX_COMPILER=clang++ \
    && cmake --build build -j$(nproc)

# Runtime stage - minimal Alpine image
FROM alpine:3.20

# Install runtime dependencies only
RUN apk add --no-cache \
    libcurl \
    libstdc++ \
    libssl3 \
    libcrypto3 \
    ca-certificates

# Copy the binary
COPY --from=builder /build/build/quickwork /usr/local/bin/quickwork

# Create handlers directory
WORKDIR /data

# Expose default port
EXPOSE 8080

# Set entrypoint
ENTRYPOINT ["quickwork"]
CMD ["-p", "8080", "-c", "/data/handlers"]
