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
