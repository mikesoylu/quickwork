# QuickWork

A minimalist serverless QuickJS runtime.

## Features

- Near instant cold starts
- Multithreaded QuickJS runtime with request isolation
- Configurable memory and CPU limits per request

## Building

Requirements:
- CMake 3.20+
- Modern C++ compiler
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

Handlers are JavaScript functions that receive a Request and return a Response. QuickWork compiles handlers to bytecode on registration for fast execution.

### Request Object

Handlers receive a Request object with:
- `method` - HTTP method (GET, POST, etc.)
- `url` - Request URL/path
- `body` - Request body as string
- `headers` - Object with request headers
- `json()` - Parse body as JSON

### Response Object

Create responses using the Response constructor:

```javascript
// Simple text response
new Response("Hello, World!")

// With status and headers
new Response("Not Found", { 
  status: 404,
  headers: { "content-type": "text/plain" }
})

// JSON helper
Response.json({ data: "value" })
Response.json({ error: "Bad Request" }, { status: 400 })
```

### Fetch API

Make HTTP requests from handlers using the standard `fetch` API:

```javascript
export default async function(req) {
  const response = await fetch("https://api.example.com/data", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key: "value" })
  });
  
  const data = await response.json();
  return Response.json(data);
}
```

The fetch response object includes:
- `status` - HTTP status code
- `ok` - Boolean indicating success (status 200-299)
- `body` - Response body as string
- `json()` - Parse body as JSON
- `text()` - Get body as string

### Timers

Use `setTimeout` for delayed execution:

```javascript
export default async function(req) {
  await new Promise(resolve => setTimeout(resolve, 100));
  return new Response("Waited 100ms");
}
```

### Crypto API

Web Crypto API for generating random values and UUIDs:

```javascript
export default function(req) {
  // Generate a UUID
  const id = crypto.randomUUID();
  
  // Generate random bytes
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  
  return Response.json({ id, bytes: Array.from(bytes) });
}
```

### ESM Imports from esm.sh

Import npm packages directly from [esm.sh](https://esm.sh) at compile time:

```javascript
import { nanoid } from "https://esm.sh/nanoid";

export default function(req) {
  return Response.json({ id: nanoid() });
}
```

```javascript
import { v4 as uuidv4 } from "https://esm.sh/uuid";

export default function(req) {
  return Response.json({ id: uuidv4() });
}
```

Modules are fetched and bundled during handler registration, so there's no runtime overhead. Transitive dependencies are automatically resolved.

### Console

Use `console.log`, `console.warn`, and `console.error` for debugging (output goes to server stderr):

```javascript
export default function(req) {
  console.log("Request received:", req.method, req.url);
  return new Response("OK");
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

QuickWork provides a built-in health check endpoint at `GET /health`:

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

You can use this in your Dockerfile:

```dockerfile
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
    CMD curl -f http://localhost:8080/health || exit 1
```
