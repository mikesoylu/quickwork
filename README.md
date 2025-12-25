# QuickWork

A modern C++ web server with a multithreaded QuickJS runtime for executing JavaScript handlers.

## Features

- Multithreaded QuickJS runtime (one runtime per thread)
- New JS context per request for isolation
- Support for sync and async handlers
- Configurable memory and CPU limits per request
- Handler caching to disk
- Modern C++20 with Boost.Beast HTTP server

## Building

Requirements:
- CMake 3.20+
- C++20 compatible compiler
- OpenSSL

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

## Usage

### Starting the Server

```bash
./quickwork [options]

Options:
  -h [ --help ]                        Show help message
  -H [ --host ] arg (=0.0.0.0)         Host to bind to
  -p [ --port ] arg (=8080)            Port to listen on
  -c [ --cache-dir ] arg (=./handlers) Handler cache directory
  -m [ --max-memory ] arg (=64)        Max memory per runtime in MB
  -t [ --max-cpu-time ] arg (=5000)    Max CPU time per request in ms
  -j [ --threads ] arg (=0)            Number of worker threads (0 = auto)
```

### Registering a Handler

POST a JavaScript handler without the `x-handler-id` header:

```bash
curl -X POST http://localhost:8080 \
  -d 'export default function(req) { return new Response("Hello!"); }'
```

Response:
```json
{"id":"abc123..."}
```

### Executing a Handler

Make any request with the `x-handler-id` header:

```bash
curl http://localhost:8080 -H "x-handler-id: abc123..."
```

## Handler API

### Request Object

Handlers receive a Request object with:
- `method` - HTTP method (GET, POST, etc.)
- `url` - Request URL/path
- `body` - Request body as string
- `headers` - Object with request headers
- `json()` - Parse body as JSON

### Response Object

Create responses using:

```javascript
// Simple text response
new Response("Hello, World!")

// With options
new Response("Not Found", { status: 404 })

// JSON response
Response.json({ data: "value" })

// With status
Response.json({ error: "Bad Request" }, { status: 400 })
```

### Examples

Sync handler:
```javascript
export default function(req) {
  return Response.json({
    method: req.method,
    url: req.url
  });
}
```

Async handler:
```javascript
export default async function(req) {
  const data = req.json();
  return Response.json({ received: data });
}
```

## Docker Deployment

QuickWork can be deployed using Docker. You can either use the provided Dockerfile directly or build it as part of a multi-stage build in your own project.

### Using the Dockerfile

```bash
# Build the image
docker build -t quickwork .

# Run the container
docker run -d -p 8080:8080 -v handlers:/data/handlers quickwork
```

### Multi-stage Build from Git

To include QuickWork in your own Docker image, you can clone and build it in a multi-stage build:

```dockerfile
# Build stage - compile QuickWork from source
FROM alpine:3.20 AS quickwork-builder

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

# Clone and build QuickWork
RUN git clone --depth 1 https://github.com/mikesoylu/quickwork.git . && \
    cmake -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=clang \
        -DCMAKE_CXX_COMPILER=clang++ && \
    cmake --build build -j$(nproc)

# Your application stage
FROM alpine:3.20

# Install runtime dependencies
RUN apk add --no-cache \
    libcurl \
    libstdc++ \
    libssl3 \
    libcrypto3 \
    ca-certificates

# Copy QuickWork binary
COPY --from=quickwork-builder /build/build/quickwork /usr/local/bin/quickwork

# Copy your application files
COPY . /app
WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["quickwork"]
CMD ["-p", "8080", "-c", "/app/handlers"]
```

### Configuration Options

The Docker container accepts the same command-line options:

```bash
# Custom port and cache directory
docker run -d -p 3000:3000 quickwork -p 3000 -c /data/cache

# Limit resources
docker run -d -p 8080:8080 quickwork -m 32 -t 1000 -j 4

# With volume for persistent handler cache
docker run -d -p 8080:8080 \
    -v quickwork-cache:/data/handlers \
    quickwork
```

### Health Check

You can add a health check to your container:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD curl -f http://localhost:8080 -H "x-handler-id: healthcheck" || exit 1
```

## Architecture

```
                    +------------------+
                    |   HTTP Server    |
                    | (Boost.Beast)    |
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
    +---------v---------+         +---------v---------+
    |    Thread Pool    |         |   Handler Store   |
    |                   |         |                   |
    | +---------------+ |         | - SHA256 hash ID  |
    | | QuickJS RT 1  | |         | - Disk cache      |
    | +---------------+ |         | - Memory cache    |
    | +---------------+ |         +-------------------+
    | | QuickJS RT 2  | |
    | +---------------+ |
    | +---------------+ |
    | | QuickJS RT N  | |
    | +---------------+ |
    +-------------------+
```

Each worker thread has its own QuickJS runtime. Each request gets a fresh context within that runtime, ensuring isolation between requests while reusing the compiled bytecode when possible.

## License

MIT
