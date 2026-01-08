# acm_proxy
# Design Document
## HTTP/HTTPS Forward Proxy Server

---

## 1. Overview
This document describes the design of a Python-based forward proxy server that supports HTTP request forwarding and HTTPS tunneling via the CONNECT method. The proxy provides basic filtering, logging, and runtime metrics while maintaining a simple and predictable concurrency model.

---

## 2. High-Level Architecture

### 2.1 Architecture Description
The proxy server operates as an intermediary between clients (browsers, command-line tools) and destination servers on the internet. Clients send HTTP or HTTPS requests to the proxy, which then forwards them to the appropriate target server or establishes a tunnel for encrypted traffic.

**Logical Architecture:**

Client → Proxy Server → Target Server


### 2.2 Core Components

#### 2.2.1 Listener / Acceptor
- Binds to a configured IP address and port
- Accepts incoming TCP connections
- Delegates accepted connections to worker threads via a thread pool

#### 2.2.2 Client Handler
- Processes exactly one client connection
- Parses HTTP request headers
- Identifies request method (HTTP or CONNECT)
- Enforces blocklist rules
- Forwards traffic to the destination server

#### 2.2.3 Filtering Engine
- Uses a domain-based blocklist
- Supports exact domain and subdomain matching
- Prevents forwarding of disallowed destinations

#### 2.2.4 Logging Subsystem
- Writes structured access logs
- Ensures thread-safe log writes
- Performs log rotation when file size exceeds configured limits

#### 2.2.5 Metrics Subsystem
- Tracks request timestamps for RPM calculation
- Counts per-host request frequency
- Periodically reports runtime statistics

---

## 3. Concurrency Model

### 3.1 Model Used
The proxy uses a **thread pool–based concurrency model**, where:
- The main thread accepts connections
- Each connection is handled by a worker thread from a bounded thread pool

### 3.2 Rationale
- Prevents unbounded thread creation
- Simplifies protocol handling using blocking sockets
- Suitable for moderate traffic workloads
- Easier to reason about compared to event-driven designs

---

## 4. Data Flow

### 4.1 Incoming Request Handling
1. Client establishes a TCP connection to the proxy
2. Proxy reads data until end-of-headers marker (CRLF CRLF)
3. Request line and headers are parsed
4. Target host and port are resolved
5. Blocklist rules are applied
6. Metrics are updated
7. Request is forwarded or tunneled

---

### 4.2 HTTP Request Forwarding Flow
- Proxy reads optional request body using Content-Length
- Establishes connection to target server
- Forwards full HTTP request
- Streams response back to the client
- Closes connections after completion

---

### 4.3 HTTPS CONNECT Tunneling Flow
- Client sends CONNECT host:port
- Proxy validates destination
- Proxy connects to target server
- Proxy responds with "200 Connection Established"
- Raw TCP tunnel is established
- Data flows bidirectionally until closure

---

## 5. Error Handling

### 5.1 Client-Side Errors
- Malformed requests → 400 Bad Request
- Missing or invalid host → 400 Bad Request

### 5.2 Proxy / Network Errors
- Target unreachable → 502 Bad Gateway
- Connection failure → 502 Bad Gateway

### 5.3 Policy Errors
- Blocked domain → 403 Forbidden

---

## 6. Limitations

### 6.1 Protocol Limitations
- HTTP/1.1 only
- No HTTP keep-alive
- No chunked transfer encoding
- No HTTP/2 or HTTP/3

### 6.2 Performance Limitations
- Blocking I/O
- One worker thread per active connection
- Not optimized for very high concurrency

### 6.3 Feature Limitations
- No caching
- No authentication
- No TLS interception

---

## 7. Security Considerations

### 7.1 Implemented Measures
- Domain-based request filtering
- Thread pool size limits
- Socket timeouts
- Graceful shutdown handling

### 7.2 Known Risks
- Open proxy abuse due to lack of authentication
- Potential denial-of-service through connection exhaustion
- No inspection of encrypted HTTPS traffic

---

## 8. Summary
The proxy server is designed for clarity and correctness, prioritizing understandable control flow and protocol compliance over scalability. The architecture and concurrency model are well-suited for educational use, controlled environments, and moderate traffic scenarios.

[▶ Watch demo](./demo_vid[1].mp4)
