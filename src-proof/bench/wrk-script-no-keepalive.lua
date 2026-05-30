-- wrk Lua script that forces a fresh TLS handshake per request
-- by sending Connection: close. Required because we are measuring
-- per-handshake cost, not steady-state throughput on a warm connection.
wrk.headers["Connection"] = "close"
