-- wrk Lua script to disable connection reuse
-- Forces new TLS handshake for every request
-- Simply sends Connection: close header

request = function()
    return wrk.format("GET", "/", {["Connection"] = "close"})
end