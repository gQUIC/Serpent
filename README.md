# Serpent

A production-ready Go implementation of the Serpent protocol.

## Overview

`Serpent` provides a robust, high-performance protocol implementation in Go. It is designed for reliability, ease of integration, and suitability for real-world deployments. The Serpent protocol can be used as a transport or messaging layer in distributed systems, games, and other latency-sensitive applications.

## Features

- **Reliable transport**: Guarantees message delivery and ordering.
- **Message-oriented**: Maintains clear message boundaries.
- **Efficient**: Optimized for low-latency and high-throughput scenarios.
- **Production-ready**: Designed for stability and long-term maintenance.
- **Pure Go**: No CGo or external dependencies.

## Installation

```bash
go get github.com/gQUIC/Serpent
```

## Quick Start

### Server Example

```go
package main

import (
    "fmt"
    "log"
    "github.com/gQUIC/Serpent"
)

func main() {
    // Start a Serpent server
    server, err := serpent.Listen("0.0.0.0:8080")
    if err != nil {
        log.Fatalf("Listen error: %v", err)
    }
    defer server.Close()

    fmt.Println("Serpent server listening on 0.0.0.0:8080")

    for {
        conn, err := server.Accept()
        if err != nil {
            log.Printf("Accept error: %v", err)
            continue
        }
        go handleConn(conn)
    }
}

func handleConn(conn *serpent.Conn) {
    defer conn.Close()
    buf := make([]byte, 2048)
    for {
        n, err := conn.Read(buf)
        if err != nil {
            log.Printf("Read error: %v", err)
            return
        }
        fmt.Printf("Received: %s\n", string(buf[:n]))
        // Echo back
        conn.Write([]byte("ACK"))
    }
}
```

### Client Example

```go
package main

import (
    "fmt"
    "log"
    serpent "github.com/gQUIC/Serpent"
)

func main() {
    conn, err := serpent.Dial("127.0.0.1:8080")
    if err != nil {
        log.Fatalf("Dial error: %v", err)
    }
    defer conn.Close()

    msg := "Hello, Serpent!"
    _, err = conn.Write([]byte(msg))
    if err != nil {
        log.Fatalf("Write error: %v", err)
    }

    buf := make([]byte, 2048)
    n, err := conn.Read(buf)
    if err != nil {
        log.Fatalf("Read error: %v", err)
    }
    fmt.Printf("Received: %s\n", string(buf[:n]))
}
```

## API Reference

### Server

- `serpent.Listen(address string) (*serpent.Listener, error)`
- `(*serpent.Listener).Accept() (*serpent.Conn, error)`
- `(*serpent.Listener).Close() error`

### Client

- `serpent.Dial(address string) (*serpent.Conn, error)`

### Connection

- `(*serpent.Conn).Read([]byte) (int, error)`
- `(*serpent.Conn).Write([]byte) (int, error)`
- `(*serpent.Conn).Close() error`

## Configuration

Serpent provides options for tuning protocol parameters (timeouts, buffer sizes, etc.) via optional parameters or configuration structures. Refer to the GoDoc/API documentation for details.

## Production Deployment

- Deploy behind a secure firewall or NAT as needed.
- Adjust buffer sizes for high-bandwidth or low-latency use cases.
- Monitor logs and connection metrics for operational health.
- Always close connections gracefully to free resources.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Support

For issues or feature requests, please open an issue on GitHub.

---
