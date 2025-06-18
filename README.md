# EgoBGP

A minimal BGP announcer that dynamically announces/withdraws prefixes based on HTTP health checks.

## Required Environment Variables

- `LOCAL_ASN` - Local AS number
- `ROUTER_ID` - BGP router ID (IP address)
- `PEER_IP` - BGP peer IP address
- `PEER_ASN` - BGP peer AS number
- `NEXT_HOP_IPV4` - IPv4 next-hop address for IPv4 prefix announcements
- `NEXT_HOP_IPV6` - IPv6 next-hop address for IPv6 prefix announcements
- `ANNOUNCED_PREFIXES` - Prefixes to announce in CIDR format, separated by commas if there are multiple
- `HEALTH_CHECK_URL` - Health check endpoint URL

## Optional Environment Variables

- `LOCAL_PORT` - Local BGP port to listen on (default: 179)
- `LOCAL_ADDRESS` - Local IP address to bind to (default: wildcard 0.0.0.0)
- `PEER_PORT` - BGP peer port (default: 179)
- `HEALTH_CHECK_INTERVAL` - Interval in seconds (default: 10)
- `SUCCESS_THRESHOLD` - Consecutive successes needed to announce (default: 1)
- `FAILURE_THRESHOLD` - Consecutive failures needed to withdraw (default: 4)

## Quick Start

Build:
```bash
go build -o egobgp
```

Run (IPv4 only):
```bash
export LOCAL_ASN=65100
export ROUTER_ID=192.0.2.10
export PEER_IP=192.0.2.20
export PEER_ASN=65200
export NEXT_HOP_IPV4=192.0.2.30
export ANNOUNCED_PREFIXES=203.0.113.100/32
export HEALTH_CHECK_URL=http://myapp:8080/health
export LOCAL_ADDRESS=::1
./egobgp
```

Run (IPv6 only):
```bash
export LOCAL_ASN=65100
export ROUTER_ID=192.0.2.10
export PEER_IP=::1
export PEER_ASN=65200
export NEXT_HOP_IPV6=::1
export ANNOUNCED_PREFIXES=2001:db8::/48
export HEALTH_CHECK_URL=http://myapp:8080/health
export LOCAL_ADDRESS=::1
./egobgp
```

Run (Mixed IPv4 and IPv6):
```bash
export LOCAL_ASN=65100
export ROUTER_ID=192.0.2.10
export PEER_IP=::1
export PEER_ASN=65200
export NEXT_HOP_IPV4=192.0.2.30
export NEXT_HOP_IPV6=::1
export ANNOUNCED_PREFIXES=203.0.113.100/32,2001:db8::/48
export HEALTH_CHECK_URL=http://myapp:8080/health
export LOCAL_ADDRESS=::1
./egobgp
```

## Docker

Build:
```bash
docker build -t egobgp .
```

Run (IPv4 only):
```bash
docker run -d \
  -p 179:179 \
  -e LOCAL_ASN=65100 \
  -e ROUTER_ID=192.0.2.10 \
  -e PEER_IP=192.0.2.20 \
  -e PEER_ASN=65200 \
  -e NEXT_HOP_IPV4=192.0.2.30 \
  -e ANNOUNCED_PREFIXES=203.0.113.100/32 \
  -e HEALTH_CHECK_URL=http://myapp:8080/health \
  -e LOCAL_ADDRESS=::1 \
  egobgp
```

Run (Mixed IPv4 and IPv6):
```bash
docker run -d \
  -p 179:179 \
  -e LOCAL_ASN=65100 \
  -e ROUTER_ID=192.0.2.10 \
  -e PEER_IP=::1 \
  -e PEER_ASN=65200 \
  -e NEXT_HOP_IPV4=192.0.2.30 \
  -e NEXT_HOP_IPV6=::1 \
  -e ANNOUNCED_PREFIXES=203.0.113.100/32,2001:db8::/48 \
  -e HEALTH_CHECK_URL=http://myapp:8080/health \
  -e LOCAL_ADDRESS=::1 \
  egobgp
```

## Features

- Uses GoBGP as an embedded BGP server
- Configurable local ASN and router ID
- Single BGP peer support with configurable IP and ASN
- Separate next-hop configuration for IPv4 and IPv6 prefixes
- Periodic HTTP health checks (configurable interval)
- Configurable thresholds for consecutive successes/failures
- Dynamic prefix announcement based on health check status
- Support for mixed IPv4 and IPv6 prefix announcements
- Lightweight with minimal dependencies

## Behavior

1. The application starts a BGP server with the configured local ASN and router ID
2. It establishes a BGP session with the configured peer
3. Every N seconds (configurable), it performs an HTTP GET request to the health check URL
4. Health check success/failure handling:
   - After SUCCESS_THRESHOLD consecutive successful checks (HTTP 200):
     * All configured prefixes are announced to the peer (if not already announced)
   - After FAILURE_THRESHOLD consecutive failed checks (non-200 or error):
     * All configured prefixes are withdrawn from the peer (if currently announced)
5. The application maintains counters for consecutive successes and failures
6. Success resets the failure counter and vice versa
7. Each prefix uses the appropriate next-hop address based on its address family (IPv4 or IPv6)
