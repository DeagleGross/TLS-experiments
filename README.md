# TLS tests

> C server
1) `make`
2) `./src-c/tls_handshake_server 8443`
3) run `wrk -t4 -c50 -d10s https://localhost:8443/ --latency` client test