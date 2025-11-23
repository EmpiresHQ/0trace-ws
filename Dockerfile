# Multi-stage build for zerotrace-ws
FROM node:24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    curl \
    gcc \
    g++ \
    make \
    python3 \
    musl-dev \
    linux-headers

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY napi.config.json ./
COPY Cargo.toml ./

# Install Node dependencies
RUN npm ci

# Copy source code
COPY src ./src
COPY *.ts ./
COPY public ./public

# Build Rust native module
RUN npm run build

# Production stage
FROM node:24-alpine

# Install runtime dependencies only
RUN apk add --no-cache libgcc libstdc++

WORKDIR /app

# Copy built artifacts from builder
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/index.node ./
COPY --from=builder /app/index.js ./
COPY --from=builder /app/index.d.ts ./
COPY --from=builder /app/*.ts ./
COPY --from=builder /app/public ./public

# Expose ports
EXPOSE 3000 8080

# Run the server
CMD ["node", "--experimental-strip-types", "server.ts"]
