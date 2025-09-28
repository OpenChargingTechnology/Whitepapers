# Resilient, high-available and pooled parallel Connections

Resilient and high-available connections are established through redundant endpoints and transparent failover, while a pool of concurrent persistent connections ensures low-latency parallel request handling and avoids classical head-of-the-line blocking.

- Reconnection logic
  - Initial waiting time
  - Backoff
- H/A settings
  - DNS-SRV records
  - Static configuration within the device model
- Extended DNS-SRV records
  - Server public keys for security
  - Information how many concurrent connections are allowed for connection pooling
- Concurrent Connection Pools
  - Shall some connections be dedicated to certain protocol functions, e.g. RFID Auth/RemoteStarts within EV roaming over a dedicated connection pool for lowest latency and to avoid head-of-the-line blockings?
